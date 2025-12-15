"""
Minimal Windows trainer for `point-cracker.exe`.

What it does:
- Launches the target EXE in a **suspended** state.
- Computes the process image base (works for native x64 and WOW64).
- Writes a patch-site trampoline at `image_base + PATCH_SITE_RVA`:
    `E9 <rel32> 90 90 90 90`  ->  `jmp <code cave>; nop*4`
  This overwrites 9 bytes at the patch site (commonly a 2-byte `xor edx, edx` plus a 7-byte `lea rcx, [...]`).
- Writes a code cave stub at `image_base + CODE_CAVE_RVA`:
  - `mov edx, <EDX_VALUE>`
  - `mov rcx, <absolute VA of printf format string>`
  - `sub rsp, 0x28` (Win64 shadow space)
  - `call` through the target's printf IAT slot (same call style as the original code)
  - `add rsp, 0x28`
  - `jmp` back to the original flow
- Verifies the write, then resumes the main thread.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time
from pathlib import Path

# --- target-specific configuration ---
# RVAs are relative virtual addresses inside the module (not file offsets).
EXE_PATH = r"..\binary\point-cracker.exe"  # path to the EXE to run/patch
EDX_VALUE = 99  # value printed by printf (%d)

# Patch site: overwrite 9 bytes with `jmp cave` (5 bytes) + `nop*4`.
PATCH_SITE_RVA = 0x11929

# Code cave location where we write our stub.
CODE_CAVE_RVA = 0x11955

# Return after cave: instruction immediately after the 9-byte overwrite.
# You showed the console-print call at RVA 0x11932, and 0x11929 + 9 == 0x11932.
RETURN_RVA = 0x11932

# printf format string RVA ("Your count points is %d").
PRINTF_FORMAT_RVA = 0x13000

# printf IAT slot RVA (the slot contains the imported function pointer).
PRINTF_IAT_RVA = 0x15DF

# After resuming the process, wait a bit and re-check that our patches are still present.
POST_RESUME_CHECK_DELAY_S = 0.25

# Some Python builds don't expose SIZE_T in ctypes.wintypes
try:
    SIZE_T = wt.SIZE_T  # type: ignore[attr-defined]
except AttributeError:
    SIZE_T = ctypes.c_size_t

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)


class STARTUPINFOW(ctypes.Structure):
    """Windows `STARTUPINFO` for `CreateProcessW`.

    Purpose here: required to call `CreateProcessW`; we only set `cb` and leave
    the rest as defaults.
    """

    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    """Windows `PROCESS_INFORMATION` output from `CreateProcessW`.

    Purpose here: gives us the new process/thread handles and PID/TID so we can
    patch memory, resume the main thread, and close handles.
    """

    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """`NtQueryInformationProcess(ProcessBasicInformation=0)` output.

    Purpose here: provides the PEB address; we read ImageBaseAddress from the PEB
    to compute final VAs from RVAs (`image_base + <RVA>`).
    """

    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def die(msg: str) -> None:
    """Raise an `OSError` with the current Win32 last-error attached."""
    err = ctypes.get_last_error()
    raise OSError(err, f"{msg} (WinError {err}: {ctypes.FormatError(err)})")


def rpm(hproc: int, addr: int, size: int) -> bytes:
    """Read `size` bytes from `hproc` at absolute address `addr`."""
    buf = (ctypes.c_ubyte * size)()
    read = SIZE_T()
    if not K32.ReadProcessMemory(wt.HANDLE(hproc), wt.LPCVOID(addr), ctypes.byref(buf), size, ctypes.byref(read)):
        die("ReadProcessMemory failed")
    return bytes(buf[: int(read.value)])


def wpm(hproc: int, addr: int, data: bytes) -> None:
    """Write `data` into `hproc` at absolute address `addr`."""
    written = SIZE_T()
    if not K32.WriteProcessMemory(wt.HANDLE(hproc), wt.LPVOID(addr), data, len(data), ctypes.byref(written)):
        die("WriteProcessMemory failed")
    if int(written.value) != len(data):
        raise OSError(f"WriteProcessMemory short write: {int(written.value)}/{len(data)}")


def is_wow64(hproc: int) -> bool:
    """Return True if the target process is a WOW64 (32-bit) process on 64-bit Windows."""
    b = wt.BOOL()
    if not K32.IsWow64Process(wt.HANDLE(hproc), ctypes.byref(b)):
        die("IsWow64Process failed")
    return bool(b.value)


def image_base(hproc: int) -> int:
    """Return the module image base address of the main executable in `hproc`."""
    # WOW64: NtQueryInformationProcess(ProcessWow64Information=26) => PEB32 addr
    if is_wow64(hproc):
        peb32 = ctypes.c_void_p()
        ret_len = wt.ULONG()
        status = NTDLL.NtQueryInformationProcess(
            wt.HANDLE(hproc), wt.ULONG(26), ctypes.byref(peb32), wt.ULONG(ctypes.sizeof(peb32)), ctypes.byref(ret_len)
        )
        if int(status) != 0 or not peb32.value:
            raise OSError(int(status), f"NtQueryInformationProcess(26) failed NTSTATUS 0x{int(status):08X}")
        return struct.unpack("<I", rpm(hproc, int(peb32.value) + 0x08, 4))[0]

    # Native: NtQueryInformationProcess(ProcessBasicInformation=0) => PEB64 addr
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = wt.ULONG()
    status = NTDLL.NtQueryInformationProcess(
        wt.HANDLE(hproc), wt.ULONG(0), ctypes.byref(pbi), wt.ULONG(ctypes.sizeof(pbi)), ctypes.byref(ret_len)
    )
    if int(status) != 0 or not pbi.PebBaseAddress:
        raise OSError(int(status), f"NtQueryInformationProcess(0) failed NTSTATUS 0x{int(status):08X}")
    return struct.unpack("<Q", rpm(hproc, int(pbi.PebBaseAddress) + 0x10, 8))[0]


def launch_suspended(exe: Path) -> tuple[int, int, int]:
    """Create `exe` in a suspended state. Returns (pid, hProcess, hThread)."""
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f"\"{str(exe)}\"")
    K32.CreateProcessW.restype = wt.BOOL
    if not K32.CreateProcessW(wt.LPCWSTR(str(exe)), cmd, None, None, False, 0x00000004, None, None, ctypes.byref(si), ctypes.byref(pi)):  # CREATE_SUSPENDED
        die("CreateProcessW(CREATE_SUSPENDED) failed")
    return int(pi.dwProcessId), int(pi.hProcess), int(pi.hThread)


def jmp_rel32(src: int, dst: int) -> bytes:
    """Encode `jmp rel32` from absolute VA `src` to absolute VA `dst`."""
    disp = dst - (src + 5)
    return b"\xE9" + struct.pack("<i", disp)
    

def call_iat_rip(iat_va: int, call_insn_va: int) -> bytes:
    """Encode `call qword ptr [rip+disp32]` where RIP is `call_insn_va + 6`."""
    disp = iat_va - (call_insn_va + 6)
    return b"\xFF\x15" + struct.pack("<i", disp)


def call_rel32(src: int, dst: int) -> bytes:
    disp = dst - (src + 5)
    return b"\xE8" + struct.pack("<i", disp)


if __name__ == "__main__":
    exe = Path(EXE_PATH)
    if not exe.is_file():
        print(f"[-] EXE not found: {exe}", file=sys.stderr)
        raise SystemExit(1)

    # patch = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32

    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)

        # TODO go over this again and rewrite it to solidify knowledge.
        
        addr = base + PATCH_SITE_RVA  # patch site VA
        addr_cave = base + CODE_CAVE_RVA  # code cave VA
        addr_return = base + RETURN_RVA  # return VA
        addr_str = base + PRINTF_FORMAT_RVA  # printf format string VA
        addr_printf_wrapper = base + PRINTF_IAT_RVA  # printf IAT slot VA (contains pointer to printf)

        patch = jmp_rel32(addr, addr_cave) # EB = JMP rel8 (short jump)
        patch += b"\x90\x90\x90\x90"						# add the proceeding 4 NOPs

        patch_cave = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32
        patch_cave += b"\x48\xB9" + struct.pack("<Q", addr_str)  # mov rcx, imm64 (absolute VA)

        # sub rsp, 0x28 (4 bytes)
        patch_cave += b"\x48\x83\xEC\x28"

        # call qword ptr [rip+disp32] to printf IAT (6 bytes)
        call_addr = addr_cave + len(patch_cave)
        patch_cave += call_rel32(call_addr, addr_printf_wrapper + 1)

        # add rsp, 0x28 (4 bytes)
        patch_cave += b"\x48\x83\xC4\x28"

        # jmp back to original flow (5 bytes)
        jmp_back_addr = addr_cave + len(patch_cave)
        patch_cave += jmp_rel32(jmp_back_addr, addr_return)


        print(f"[+] PID:        {pid}")
        print(f"[+] ImageBase:   0x{base:016X}")
        print(f"[+] PatchSite:   RVA 0x{PATCH_SITE_RVA:X} -> VA 0x{addr:016X}")
        print(f"[+] CodeCave:    RVA 0x{CODE_CAVE_RVA:X} -> VA 0x{addr_cave:016X}")
        print(f"[+] Return:      RVA 0x{RETURN_RVA:X} -> VA 0x{addr_return:016X}")
        print(f"[+] FormatStr:   RVA 0x{PRINTF_FORMAT_RVA:X} -> VA 0x{addr_str:016X}")
        print(f"[+] printf wrapper:  RVA 0x{PRINTF_IAT_RVA:X} -> VA 0x{addr_printf_wrapper:016X}")
        print(f"[+] EDX_VALUE:   {EDX_VALUE}")

        old_site = rpm(hproc, addr, len(patch))
        old_cave = rpm(hproc, addr_cave, len(patch_cave))

        print(f"[+] Trampoline ({len(patch)} bytes):")
        print(f"    Old: {old_site.hex(' ').upper()}")
        print(f"    New: {patch.hex(' ').upper()}")

        print(f"[+] CodeCave stub ({len(patch_cave)} bytes):")
        print(f"    Old: {old_cave.hex(' ').upper()}")
        print(f"    New: {patch_cave.hex(' ').upper()}")

        # Write cave first; then arm the trampoline.
        print("[+] Writing code cave stub...")
        wpm(hproc, addr_cave, patch_cave)
        if rpm(hproc, addr_cave, len(patch_cave)) != patch_cave:
            print("[-] Verify code cave failed", file=sys.stderr)
            raise SystemExit(3)

        print("[+] Writing trampoline...")
        wpm(hproc, addr, patch)
        if rpm(hproc, addr, len(patch)) != patch:
            print("[-] Verify trampoline failed", file=sys.stderr)
            raise SystemExit(4)

        print("[+] Patched OK; resuming.")
        K32.ResumeThread(wt.HANDLE(hthread))
        print(f"[+] Post-resume sanity check: sleeping {POST_RESUME_CHECK_DELAY_S:.2f}s then re-reading patch sites...")
        time.sleep(POST_RESUME_CHECK_DELAY_S)

        try:
            site_now = rpm(hproc, addr, len(patch))
            cave_now = rpm(hproc, addr_cave, len(patch_cave))
        except OSError as e:
            # This can happen if the process exits quickly after resume, or if access is lost.
            print(f"[-] Post-resume re-read failed: {e}", file=sys.stderr)
            raise SystemExit(5)

        ok_site = site_now == patch
        ok_cave = cave_now == patch_cave

        print(f"[+] PatchSite intact: {ok_site}")
        if not ok_site:
            print(f"    Expected: {patch.hex(' ').upper()}")
            print(f"    Actual:   {site_now.hex(' ').upper()}")

        print(f"[+] CodeCave intact:  {ok_cave}")
        if not ok_cave:
            print(f"    Expected: {patch_cave.hex(' ').upper()}")
            print(f"    Actual:   {cave_now.hex(' ').upper()}")

        if not (ok_site and ok_cave):
            raise SystemExit(6)
        raise SystemExit(0)
    finally:
        K32.CloseHandle(wt.HANDLE(hthread))
        K32.CloseHandle(wt.HANDLE(hproc))
