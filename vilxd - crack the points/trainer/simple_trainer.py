"""
Minimal Windows trainer for `point-cracker.exe`.

What it does:
- Launches the target EXE in a **suspended** state.
- Computes the process image base (works for native x64 and WOW64).
- Writes a tiny patch at `image_base + PATCH_RVA`:
    `BA <imm32>`  ->  `mov edx, imm32`
- Verifies the write, then resumes the main thread.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
from pathlib import Path

# --- target-specific configuration ---
# `PATCH_RVA` is a relative virtual address (RVA) inside the module (not a file offset).
EXE_PATH = r"..\binary\point-cracker.exe"  # path to the EXE to run/patch
EDX_VALUE = 99  # imm32 for `mov edx, imm32`

PATCH_RVA = 0x11929  # where to write (RVA)
PATCH_CAVE = 0x11955 # where the code cave will be located
PATCH_RETURN = 0x11937 # where the code cave will return to
PATCH_STR_DEF = 0x13000 # where "Your count points is %d" is located

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
    to compute the final patch address (`image_base + PATCH_RVA`).
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


if __name__ == "__main__":
    exe = Path(EXE_PATH)
    if not exe.is_file():
        print(f"[-] EXE not found: {exe}", file=sys.stderr)
        raise SystemExit(1)

    # patch = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32

    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)
        
        addr = base + PATCH_RVA # address to `xor edx, edx` instruction we will be patching
        addr_cave = base + PATCH_CAVE # address to the code cave
        addr_return = base + PATCH_RETURN # address to the return address

        patch = b"\xEB" + addr_cave.to_bytes(4, 'little') # EB = JMP rel8 (short jump)
        patch_cave = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32
        # patch_cave += 

        print(f"[+] PID: {pid}")
        print(f"[+] ImageBase: 0x{base:016X}")
        print(f"[+] Patch: RVA 0x{PATCH_RVA:X} -> VA 0x{addr:016X}")
        print(f"[+] Old: {rpm(hproc, addr, len(patch)).hex(' ').upper()}")
        print(f"[+] New: {patch.hex(' ').upper()}  (mov edx, {EDX_VALUE})")
        
        print("[+] Code Cave:")
        print(f"[+] Patch: RVA 0x{PATCH_RVA:X} -> VA 0x{addr:016X}")

        wpm(hproc, addr, patch)
        if rpm(hproc, addr, len(patch)) != patch:
            print("[-] Verify failed", file=sys.stderr)
            raise SystemExit(3)

        print("[+] Patched OK; resuming.")
        K32.ResumeThread(wt.HANDLE(hthread))
        raise SystemExit(0)
    finally:
        K32.CloseHandle(wt.HANDLE(hthread))
        K32.CloseHandle(wt.HANDLE(hproc))
