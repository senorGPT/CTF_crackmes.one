import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time
from pathlib import Path
from typing import Optional

# Some Python builds don't expose ULONG_PTR in ctypes.wintypes
try:
    ULONG_PTR = wt.ULONG_PTR  # type: ignore[attr-defined]
except AttributeError:
    # Pointer-sized unsigned integer
    ULONG_PTR = ctypes.c_size_t

# Some Python builds don't expose SIZE_T in ctypes.wintypes
try:
    SIZE_T = wt.SIZE_T  # type: ignore[attr-defined]
except AttributeError:
    SIZE_T = ctypes.c_size_t

# Use WinDLL w/ use_last_error so ctypes.get_last_error() is meaningful
K32 = ctypes.WinDLL("kernel32", use_last_error=True)
NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)


# Minimal rights needed for patching + verification
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

CREATE_SUSPENDED = 0x00000004

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * wt.MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", wt.LPBYTE),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * wt.MAX_PATH),
    ]


def _raise_last_error(prefix: str) -> "None":
    err = ctypes.get_last_error()
    if err == 0:
        # Best-effort fallback; should be rare when using WinDLL(use_last_error=True)
        try:
            err = int(K32.GetLastError())
        except Exception:
            err = 0
    raise OSError(err, f"{prefix} failed with WinError {err}: {ctypes.FormatError(err)}")


def find_pid_by_name(exe_name: str) -> Optional[int]:
    """Return the first PID whose process executable name matches exe_name (case-insensitive)."""
    snap = K32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wt.HANDLE(-1).value:
        _raise_last_error("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)")

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)

        if not K32.Process32FirstW(snap, ctypes.byref(pe)):
            _raise_last_error("Process32FirstW")

        target = exe_name.lower()
        while True:
            if pe.szExeFile.lower() == target:
                return int(pe.th32ProcessID)
            if not K32.Process32NextW(snap, ctypes.byref(pe)):
                break
        return None
    finally:
        K32.CloseHandle(snap)


def get_module_base(pid: int, module_name: str) -> int:
    """Return module base address for module_name in process pid."""
    snap = K32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == wt.HANDLE(-1).value:
        _raise_last_error("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)")

    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)

        if not K32.Module32FirstW(snap, ctypes.byref(me)):
            _raise_last_error("Module32FirstW")

        target = module_name.lower()
        while True:
            if me.szModule.lower() == target:
                return ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
            if not K32.Module32NextW(snap, ctypes.byref(me)):
                break
        raise FileNotFoundError(f"Module not found in PID {pid}: {module_name!r}")
    finally:
        K32.CloseHandle(snap)


def is_wow64_process(hproc: int) -> bool:
    """Return True if target process is a 32-bit (WOW64) process on 64-bit Windows."""
    # On 32-bit Windows, IsWow64Process returns FALSE for all processes.
    is_wow64 = wt.BOOL()
    ok = K32.IsWow64Process(wt.HANDLE(hproc), ctypes.byref(is_wow64))
    if not ok:
        _raise_last_error("IsWow64Process")
    return bool(is_wow64.value)


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def nt_query_information_process(hproc: int, info_class: int, out_buf, out_len: int) -> None:
    """
    Wrapper for NtQueryInformationProcess.
    Raises on non-zero NTSTATUS.
    """
    return_len = wt.ULONG()
    status = NTDLL.NtQueryInformationProcess(
        wt.HANDLE(hproc),
        wt.ULONG(info_class),
        ctypes.byref(out_buf),
        wt.ULONG(out_len),
        ctypes.byref(return_len),
    )
    if int(status) != 0:
        raise OSError(int(status), f"NtQueryInformationProcess({info_class}) failed with NTSTATUS 0x{int(status):08X}")


def get_main_image_base_via_peb(hproc: int) -> int:
    """
    Get the main module ImageBaseAddress by reading the remote PEB.
    Works well for CREATE_SUSPENDED processes (no module snapshot needed).
    """
    wow64 = is_wow64_process(hproc)

    if wow64:
        # ProcessWow64Information (26) returns the 32-bit PEB address for WOW64 processes.
        peb32 = ctypes.c_void_p()
        nt_query_information_process(hproc, 26, peb32, ctypes.sizeof(peb32))
        peb32_addr = int(peb32.value or 0)
        if peb32_addr == 0:
            raise OSError("ProcessWow64Information returned NULL PEB32")
        # PEB32.ImageBaseAddress offset = 0x08, pointer is 32-bit
        data = read_memory(hproc, peb32_addr + 0x08, 4)
        (image_base,) = struct.unpack("<I", data)
        return int(image_base)

    # Non-WOW64 (native 64-bit) process:
    pbi = PROCESS_BASIC_INFORMATION()
    nt_query_information_process(hproc, 0, pbi, ctypes.sizeof(pbi))  # ProcessBasicInformation
    peb_addr = int(pbi.PebBaseAddress or 0)
    if peb_addr == 0:
        raise OSError("ProcessBasicInformation returned NULL PEB")
    # PEB.ImageBaseAddress offset = 0x10 in PEB64, pointer is 64-bit
    data = read_memory(hproc, peb_addr + 0x10, 8)
    (image_base,) = struct.unpack("<Q", data)
    return int(image_base)


def get_module_base_with_retry(pid: int, module_name: str, *, retries: int = 20, delay_s: float = 0.05) -> int:
    """
    Toolhelp module snapshots can fail transiently (especially right after CREATE_SUSPENDED).
    Retry a bit before giving up.
    """
    last_err: Optional[BaseException] = None
    for _ in range(retries):
        try:
            return get_module_base(pid, module_name)
        except OSError as e:
            last_err = e
            # ERROR_PARTIAL_COPY (299) can show up in bitness mismatch cases, but also transiently.
            time.sleep(delay_s)
    assert last_err is not None
    raise last_err


def read_memory(hproc: int, addr: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    read = SIZE_T()
    ok = K32.ReadProcessMemory(
        wt.HANDLE(hproc),
        wt.LPCVOID(addr),
        ctypes.byref(buf),
        size,
        ctypes.byref(read),
    )
    if not ok:
        _raise_last_error("ReadProcessMemory")
    return bytes(buf[: int(read.value)])


def write_memory(hproc: int, addr: int, data: bytes) -> None:
    written = SIZE_T()
    ok = K32.WriteProcessMemory(
        wt.HANDLE(hproc),
        wt.LPVOID(addr),
        data,
        len(data),
        ctypes.byref(written),
    )
    if not ok:
        _raise_last_error("WriteProcessMemory")
    if int(written.value) != len(data):
        raise OSError(f"WriteProcessMemory short write: {int(written.value)}/{len(data)} bytes")


class STARTUPINFOW(ctypes.Structure):
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
    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


def create_process_suspended(exe_path: Path, exe_args: list[str]) -> tuple[int, int, int]:
    """
    Create a new process in suspended state.
    Returns (pid, hProcess, hThread).
    """
    # Ensure nice Win32 error handling
    K32.CreateProcessW.restype = wt.BOOL

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    # CreateProcessW expects a single mutable command line string.
    cmdline = f"\"{str(exe_path)}\""
    if exe_args:
        cmdline += " " + " ".join(exe_args)
    cmdline_buf = ctypes.create_unicode_buffer(cmdline)

    ok = K32.CreateProcessW(
        wt.LPCWSTR(str(exe_path)),  # lpApplicationName
        cmdline_buf,  # lpCommandLine (mutable)
        None,  # lpProcessAttributes
        None,  # lpThreadAttributes
        False,  # bInheritHandles
        CREATE_SUSPENDED,  # dwCreationFlags
        None,  # lpEnvironment
        None,  # lpCurrentDirectory
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        _raise_last_error("CreateProcessW(CREATE_SUSPENDED)")

    return int(pi.dwProcessId), int(pi.hProcess), int(pi.hThread)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Patch point-cracker.exe either in a running process (PID/name) or by launching a new suspended process."
    )
    parser.add_argument("--pid", type=int, help="Target PID (preferred if known).")
    parser.add_argument("--process", default="point-cracker.exe", help="Process name to search for (default: point-cracker.exe).")
    parser.add_argument("--exe", type=Path, help="Path to .exe to launch suspended, patch at entry, then resume.")
    parser.add_argument(
        "--exe-args",
        nargs=argparse.REMAINDER,
        default=[],
        help="Arguments for --exe (everything after --exe-args). Example: --exe-args -- -v --mode test",
    )
    parser.add_argument("--no-resume", action="store_true", help="With --exe: keep the main thread suspended after patching.")
    parser.add_argument("--module", default="point-cracker.exe", help="Module name to patch (default: point-cracker.exe).")
    parser.add_argument("--rva", type=lambda x: int(x, 0), default=0x1193C, help="Patch RVA (default: 0x1193C).")
    parser.add_argument(
        "--edx",
        type=lambda x: int(x, 0),
        help="If set, patch bytes become: mov edx, <value> (x86/x64 opcode BA imm32). Overrides --bytes.",
    )
    parser.add_argument(
        "--bytes",
        dest="patch_bytes",
        default="B8 39 05 00 00 90",
        help="Patch bytes as hex (default: 'B8 39 05 00 00 90' => mov eax,0x539; nop).",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only show what would change; do not write.")
    args = parser.parse_args(argv)

    if args.exe is not None and (args.pid is not None or (args.process and args.process != "point-cracker.exe")):
        # Not strictly invalid, but ambiguous. Keep it simple.
        print("[-] Use either --exe OR (--pid/--process), not both.", file=sys.stderr)
        return 2

    if args.edx is not None:
        # x86/x64: mov edx, imm32 => BA <imm32 little-endian>
        patch_bytes = b"\xBA" + struct.pack("<I", args.edx & 0xFFFFFFFF)
    else:
        try:
            patch_bytes = bytes(int(b, 16) for b in args.patch_bytes.split())
        except ValueError:
            print("[-] Invalid --bytes. Expected space-separated hex like: 'B8 39 05 00 00 90'", file=sys.stderr)
            return 2

    # Set return types for handle validity checks
    K32.OpenProcess.restype = wt.HANDLE
    K32.CreateToolhelp32Snapshot.restype = wt.HANDLE

    pid: int
    hproc: int
    hthread: Optional[int] = None
    launched_exe_name: Optional[str] = None

    if args.exe is not None:
        exe_path = args.exe
        if not exe_path.is_file():
            print(f"[-] --exe not found: {exe_path}", file=sys.stderr)
            return 1
        pid, hproc, hthread = create_process_suspended(exe_path, args.exe_args)
        launched_exe_name = exe_path.name
        # If user didn't override module (left default), patch the launched EXE module.
        if args.module == "point-cracker.exe":
            args.module = exe_path.name
        print(f"[+] Launched suspended process: PID {pid}")
    else:
        pid = args.pid if args.pid is not None else 0
        if pid == 0:
            pid = find_pid_by_name(args.process) or 0
        if pid == 0:
            print(f"[-] Could not find process by name: {args.process!r}", file=sys.stderr)
            return 1

        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        hproc = K32.OpenProcess(access, False, int(pid))
        if not hproc:
            _raise_last_error("OpenProcess")

    try:
        try:
            module_base = get_module_base_with_retry(int(pid), args.module)
        except OSError as e:
            # In --exe mode, if snapshotting modules fails (common in early suspended state),
            # fall back to reading the main ImageBaseAddress from the PEB (only for the main EXE module).
            if args.exe is not None and launched_exe_name and args.module.lower() == launched_exe_name.lower():
                err = getattr(e, "errno", None)
                print(f"[!] Module snapshot failed ({err}): {e}")
                print("[!] Falling back to PEB ImageBaseAddress for main module...")
                module_base = get_main_image_base_via_peb(hproc)
            else:
                # Improve guidance for ERROR_PARTIAL_COPY (299)
                if getattr(e, "errno", None) == 299:
                    py_bits = ctypes.sizeof(ctypes.c_void_p) * 8
                    print(
                        f"[-] WinError 299 (ERROR_PARTIAL_COPY) while enumerating modules.\n"
                        f"    This is often a 32/64-bit mismatch (Python {py_bits}-bit vs target), or snapshotting too early.\n"
                        f"    If the target is 32-bit, try running a 32-bit Python. If it is 64-bit, use 64-bit Python.\n"
                        f"    (In --exe mode, this should usually be handled by retrying; consider increasing retries if needed.)",
                        file=sys.stderr,
                    )
                raise
        patch_addr = int(module_base) + int(args.rva)

        print(f"[+] PID: {pid}")
        print(f"[+] Module: {args.module} base = 0x{module_base:016X}")
        print(f"[+] Patch: RVA 0x{int(args.rva):X} -> VA 0x{patch_addr:016X}")
        print(f"[+] New bytes ({len(patch_bytes)}): {patch_bytes.hex(' ').upper()}")

        old = read_memory(hproc, patch_addr, len(patch_bytes))
        print(f"[+] Old bytes ({len(old)}): {old.hex(' ').upper()}")

        if args.dry_run:
            print("[*] Dry run enabled; not writing.")
            # If we launched suspended, optionally keep it suspended; otherwise resume by default.
            if args.exe is not None and hthread and not args.no_resume:
                K32.ResumeThread(wt.HANDLE(hthread))
                print("[+] Resumed main thread.")
            return 0

        write_memory(hproc, patch_addr, patch_bytes)
        new = read_memory(hproc, patch_addr, len(patch_bytes))
        if new != patch_bytes:
            print(f"[-] Verification failed. Read back: {new.hex(' ').upper()}", file=sys.stderr)
            return 3

        print("[+] Patch applied and verified.")

        if args.exe is not None and hthread and not args.no_resume:
            K32.ResumeThread(wt.HANDLE(hthread))
            print("[+] Resumed main thread.")

        return 0
    finally:
        K32.CloseHandle(hproc)
        if hthread:
            K32.CloseHandle(wt.HANDLE(hthread))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
