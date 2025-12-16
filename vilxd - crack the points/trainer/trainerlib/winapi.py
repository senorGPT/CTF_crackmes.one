"""
Windows WinAPI helpers for trainers (Windows-only).

Includes:
- process launch (CREATE_SUSPENDED)
- remote memory read/write + FlushInstructionCache
- image base lookup via PEB (WOW64 + native)
"""

import ctypes
import ctypes.wintypes as wt
import struct
from pathlib import Path

# Some Python builds don't expose SIZE_T in ctypes.wintypes
try:
    SIZE_T = wt.SIZE_T  # type: ignore[attr-defined]
except AttributeError:
    SIZE_T = ctypes.c_size_t

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)

# Common WinAPI prototypes we use
K32.FlushInstructionCache.argtypes = [wt.HANDLE, wt.LPCVOID, SIZE_T]
K32.FlushInstructionCache.restype = wt.BOOL

K32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
K32.WaitForSingleObject.restype = wt.DWORD

K32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
K32.GetExitCodeProcess.restype = wt.BOOL

INFINITE = 0xFFFFFFFF
STILL_ACTIVE = 259


def die(msg: str) -> None:
    """Raise an `OSError` with the current Win32 last-error attached."""
    err = ctypes.get_last_error()
    raise OSError(err, f"{msg} (WinError {err}: {ctypes.FormatError(err)})")


def exit_code(hproc: int) -> int:
    """Return the current process exit code (or STILL_ACTIVE if still running)."""
    code = wt.DWORD()
    if not K32.GetExitCodeProcess(wt.HANDLE(hproc), ctypes.byref(code)):
        die("GetExitCodeProcess failed")
    return int(code.value)


def flush_icache(hproc: int, addr: int, size: int) -> None:
    """Flush the target process instruction cache for [addr, addr+size)."""
    if not K32.FlushInstructionCache(wt.HANDLE(hproc), wt.LPCVOID(addr), SIZE_T(size)):
        die("FlushInstructionCache failed")


class STARTUPINFOW(ctypes.Structure):
    """Windows `STARTUPINFO` for `CreateProcessW` (we only set `cb`)."""

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
    """Windows `PROCESS_INFORMATION` output from `CreateProcessW`."""

    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """`NtQueryInformationProcess(ProcessBasicInformation=0)` output."""

    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def read_process_memory(hproc: int, addr: int, size: int) -> bytes:
    """Read `size` bytes from `hproc` at absolute address `addr`."""
    buf = (ctypes.c_ubyte * size)()
    read = SIZE_T()
    if not K32.ReadProcessMemory(wt.HANDLE(hproc), wt.LPCVOID(addr), ctypes.byref(buf), size, ctypes.byref(read)):
        die("ReadProcessMemory failed")
    return bytes(buf[: int(read.value)])


def write_process_memory(hproc: int, addr: int, data: bytes) -> None:
    """Write `data` into `hproc` at absolute address `addr`."""
    written = SIZE_T()
    if not K32.WriteProcessMemory(wt.HANDLE(hproc), wt.LPVOID(addr), data, len(data), ctypes.byref(written)):
        die("WriteProcessMemory failed")
    if int(written.value) != len(data):
        raise OSError(f"WriteProcessMemory short write: {int(written.value)}/{len(data)}")
    flush_icache(hproc, addr, len(data))


def hexdump(data: bytes, start_va: int, *, width: int = 16) -> str:
    """Format bytes as a simple hex dump with addresses."""
    lines: list[str] = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hex_bytes = chunk.hex(" ").upper()
        lines.append(f"    0x{start_va + off:016X}: {hex_bytes}")
    return "\n".join(lines)


def is_wow64(hproc: int) -> bool:
    """Return True if the target process is a WOW64 (32-bit) process on 64-bit Windows."""
    b = wt.BOOL()
    if not K32.IsWow64Process(wt.HANDLE(hproc), ctypes.byref(b)):
        die("IsWow64Process failed")
    return bool(b.value)


def image_base(hproc: int) -> int:
    """Return the image base address of the main executable in `hproc` (PEB-based)."""
    # WOW64: NtQueryInformationProcess(ProcessWow64Information=26) => PEB32 addr
    if is_wow64(hproc):
        peb32 = ctypes.c_void_p()
        ret_len = wt.ULONG()
        status = NTDLL.NtQueryInformationProcess(
            wt.HANDLE(hproc),
            wt.ULONG(26),
            ctypes.byref(peb32),
            wt.ULONG(ctypes.sizeof(peb32)),
            ctypes.byref(ret_len),
        )
        if int(status) != 0 or not peb32.value:
            raise OSError(int(status), f"NtQueryInformationProcess(26) failed NTSTATUS 0x{int(status):08X}")
        return struct.unpack("<I", read_process_memory(hproc, int(peb32.value) + 0x08, 4))[0]

    # Native: NtQueryInformationProcess(ProcessBasicInformation=0) => PEB64 addr
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = wt.ULONG()
    status = NTDLL.NtQueryInformationProcess(
        wt.HANDLE(hproc),
        wt.ULONG(0),
        ctypes.byref(pbi),
        wt.ULONG(ctypes.sizeof(pbi)),
        ctypes.byref(ret_len),
    )
    if int(status) != 0 or not pbi.PebBaseAddress:
        raise OSError(int(status), f"NtQueryInformationProcess(0) failed NTSTATUS 0x{int(status):08X}")
    return struct.unpack("<Q", read_process_memory(hproc, int(pbi.PebBaseAddress) + 0x10, 8))[0]


def launch_suspended(exe: Path) -> tuple[int, int, int]:
    """Create `exe` in a suspended state. Returns (pid, hProcess, hThread)."""
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f"\"{str(exe)}\"")
    K32.CreateProcessW.restype = wt.BOOL
    ok = K32.CreateProcessW(
        wt.LPCWSTR(str(exe)),
        cmd,
        None,
        None,
        False,
        0x00000004,  # CREATE_SUSPENDED
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        die("CreateProcessW(CREATE_SUSPENDED) failed")
    return int(pi.dwProcessId), int(pi.hProcess), int(pi.hThread)


# Backwards-compatible aliases
hex_dump = hexdump
rpm = read_process_memory
wpm = write_process_memory
