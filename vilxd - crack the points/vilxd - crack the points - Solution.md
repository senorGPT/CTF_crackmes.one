# Vilxd - Crack the Points — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/690fa2f12d267f28f69b7c44  
**Author:** *vilxd*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*, *Ghidra*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.0 | 3.5 | x86-64 | C/C++ |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\vilxd - crack the points\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]

---

## 1. Executive Summary

This document captures my reverse-engineering process for the crackme `crack the points` by `vilxd`. The target is a tiny console program that prints a points value and reads an integer from stdin, but never uses that input to affect the printed output.

I successfully:

- Performed basic static reconnaissance.
- Surveyed imports. Confirmed there appears to be ***NO*** anti-debugging measures.
-  Used a string-driven entry approach (searching for the console format string) to land directly in the print path.
- Confirmed the “points” output is not derived from user input at all, it is hard-coded to 0 right before the `printf` call.
- Identified the intended solve as a “poke/patch” style challenge: make the program print points > 0 by modifying the argument passed into `printf` (register edit, patch, or runtime trainer).



---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs: **Accepts user input but does nothing**
- Outputs: "*Your count points is 0*" - "Your count points is *%d*"

### 2.2 Screens

#### Start-up

![image-20251213023218995](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213023218995.png)

#### Failure case

![image-20251213023251447](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213023251447.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*
- Decompiler: *Ghidra*
- Static tools: *CFF Explorer*, *Ghidra*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251213020825651](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213020825651.png)

Notes:
- Architecture: **PE32+** (*64-bit / x86-64*). Ghidra’s default image base of `0x140000000` and the calling convention behaviour observed in *x64dbg* both align with a *64-bit* Windows build.
- Compiler hints: *Standard Windows CRT start up* is present (`mainCRTStartup` / *CRT* init calling into user `main`). The presence of `__main` and optimized helper naming like `printf.constprop.0` suggests a typical optimizing toolchain (often *MSVC* or *MinGW-w64* builds with CRT glue).
- Packing/obfuscation signs: None observed. Entry-point inspection showed normal *CRT* `init` and a straight call into `main` with no custom stubs, no strange section behavior, and no import-hiding tricks.



### 4.2 Imports / Exports

![image-20251213020857175](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213020857175.png)

Hypotheses:
- File I/O - Unlikely. Behaviour is limited to console input/output; no evidence of file reads/writes.
- Crypto - None indicated. No crypto-related imports or “hash/encode” style strings showed up in the import surface.
- Anti-debug - None observed. No classic anti-debug imports (e.g., `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` used for debug flags), and dynamic runs did not show anti-debug behaviour.



#### 4.2.1 KERNEL32.DLL

![image-20251213020921851](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213020921851.png)



#### 4.2.2 msvcrt.dll

<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213021022160.png" alt="image-20251213021022160" style="zoom:67%;" />

<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213021035547.png" alt="image-20251213021035547" style="zoom:67%;" />



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x64dbg* yields no immediate or obvious signs of any anti-debugging logic.



### 5.2 String Driven-Entry 

Searching for string references within the target *Portable Executable* (*PE*) yields results the following results.

![image-20251213025131959](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213025131959.png)

Double clicking on the string reference for "*Your count points is %d*" brings me into the disassembly view where I start to poke and prod around. I land on a function - which looks like a `scanf` wrapper - and add a breakpoint before the first `call` instruction and restart program execution.

![image-20251213025954546](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213025954546.png)

I trace the logic out of the function and land within what appears to be the `main` function.

![image-20251213031207130](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213031207130.png)

Restarting program execution and going back into that first function I notice that after the second `call` instruction, the string is output to console. I proceed to step into that second `call` instruction.

![image-20251213030159338](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213030159338.png)

Tracing the input logic by stepping through yields little to no results. For some reason being difficult to find the comparison logic ***EVEN THOUGH*** the `main` function logic seems simple.
I believe this has to do with hidden trickery that might be going on behind the scenes.



## 6. Static Binary Analysis - Ghidra

I guess it is a good of time as any to learn a new tool, `Ghidra`.

*Ghidra* is a free open-source reverse-engineering suite created by the U.S. *National Security Agency* (*NSA*). It’s designed to analyse compiled binaries - EXEs, DLLs, firmware - without running them. In practice that means *Ghidra* takes raw machine code and reconstructs it into human-readable assembly and even *C-like* pseudocode.

Where a debugger like *x64dbg* shows "what the program is doing right now", *Ghidra* focuses on *how the program is built*:

- It identifies functions, cross-references, code vs data, and control flow.
- It has a built-in decompiler that can turn many functions into *C-style* pseudocode.
- It lets you rename functions and variables, add comments, define structs, and track how data flows through the program.

This makes it especially useful for understanding complex logic that would be painful to follow step-by-step in a live debugger such as custom serialization or parsing code, obfuscated control flow, large state machines, and library or runtime internals (`scanf/strtol`, *CRT* start-up, etc.).



#### 6.1 Ghidra - String-Driven Entry

I use the `Defined Strings` *Window* shortcut to bring up the found string references.

![image-20251215001522379](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215001522379.png)

![image-20251214232946534](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251214232946534.png)

Once again targeting the `Your count points is %d` string. Double clicking it brings me to where the string definition lives.

![image-20251215001210481](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215001210481.png)

On the right in green text we can see three *cross references* (*XREFS*); `1400001e4`, `printf.constprop.0:14000160c`, and `main:14001192b`. Focusing on the `main` reference, I double click it which brings me to the `main` function logic. My assumption from earlier was correct regarding the `main` function logic,  this assembly matches that of the assembly discovered within [x64dbg](###5.2 String Driven-Entry). Albeit, with some more information thanks to *Ghidra*.

![image-20251215004802416](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215004802416.png)

One of *Ghidra's* superpowers is that it comes with a built-in *decompiler* which turns the *assembly* into *C-like pseudo code*. *Clicking on the `main` function* - *Window* - *Decompile: main*; This opens a window with the pseudo code.

![image-20251215005714226](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215005714226.png)

This makes it clear that `DAT_140013018` represents the `points`. Let's go ahead and rename it. *Right clicking `DAT_140013018`* - *Edit Label*; I change it to `POINTS`. Now with a more human readable name, it should be a easier to spot and trace when looking at the assembly and pseudo code.
The `main` function just prints the prompt, reads an integer into a global, and exits.

*Right clicking `POINTS`* - *References* - *Show References* to Points (shortcut: *CTRL + SHIFT + F*); Opens a window with all references to the `POINTS` variable.

![image-20251215010845947](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215010845947.png)

The second reference, `LEA _Argc, [POINTS]` is the instruction from the `main` function we just came from so I ignore it. Clicking on the first reference brings us into another function, which again we aren't seeing for the first time - it's the wrapper around the `scanf` function.

![image-20251215014932508](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215014932508.png)

The confusion from earlier becomes more clear here. The only two references to the global `POINTS` variable are from the `main` and `scanf` functions. This begs the question, ***where is the comparison logic?***
I am starting to wonder if there is another function that is *indirectly* accessing the `POINTS` variable or utilizing a *return value* from some kind of *helper/wrapper* function.



### 6.2 Ghidra - *CRT* Start-up

I was starting to think that maybe there was a hidden call within `mainCRTStartup`. Going to *Navigation* - *Go To...* - *entering `entry` and clicking OK*; Jumps to the logic of `mainCRTStartup`.

![image-20251215022942646](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215022942646.png)

After completing *CRT* initialization the start-up code ultimately calls the user-defined `main` function. Which is where the actual logic of the *crackme* resides. Entry-point analysis showed *no custom logic, no hidden anti-debug checks, and no obfuscation* at **start-up**.

![image-20251215022955153](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215022955153.png)



---

## 7. Validation Path

Scratching my head in confusion and frustration, I head back to the *crackme* page and read the description again.

![image-20251215025210857](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215025210857.png)

Then I also take a look at the comments.

I believe that I've been looking at this *crackme* in the wrong way...
This is a ***patching / poke-the-variable*** challenge and not a ***find-the-correct-input*** kind of challenge... So my take away is:

- *“Use a debugger or hex editor to make the program show points > 0.”*
- Any way you achieve that (editing the global, patching `printf`, changing the string) is considered a “*solve*”.

With that in mind I head back to *x64dbg*.



### 7.1 Poking the Bear

Refresher, in *Windows x64* calling convention: 1st argument = `RCX`, 2nd = `RDX`, 3rd = `R8`, 4th = `R9`, and the rest go on the `stack` + *32-byte shadow space* that the *caller* always reserves.

I re-enable my breakpoint on the call to `scanf` wrapper within the `main` function.

![image-20251215040053299](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215040053299.png)

Stepping into it:

![image-20251215040020571](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215040020571.png)

`main` called this function as:

```c
scanf("%d", &POINTS);
```

So according to *Winx64 Calling Convection*; `RCX` == `%d` and `RDX` == `&POINTS` (`000001BC238A0000`). 

![image-20251215040442754](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215040442754.png)

With that in mind what we want is the address within `RDX` as that is the variable that is being used with the format string `%d`. *BUT*, the problem here is that `RDX` will be dynamic - IE, on the next subsequent run it will not be `000001BC238A0000` but point to a different address.

![image-20251215040656935](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215040656935.png)



#### 7.1.1 Finding a Static Offset

Going back to *Ghidra*, I double click on the `POINTS` variable which brings me to it's definition.

![image-20251215041453302](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215041453302.png)

I can see that the address of `POINTS` is `0x140013018`. *Ghidra’s* addresses start the image at **`0x140000000`**. So `0x140013018` is `0x13018` bytes *after* the image base (`0x140013018` - `0x140000000` = `0x13018`). That `0x13018` is the *Relative Virtual Address* (*RVA*). 
*Address Space Layout Randomization* (*ASLR*) will move the whole module at runtime, but the *RVA* stays constant. So we can treat `0x13018` as the static offset to the read-only data.

This is where I realize I have made a mistake. I was mixing up things from *x64dbg* and *Ghidra*. The address above in *Ghidra* is the format string, not the actual `POINTS` variable. That’s why it lives in `.rdata` and is read-only. I have been chasing another red-herring.

*Occam's Razor* is a problem-solving principle that states when faced with competing explanations, the simplest one is usually the best.
Going back into the `main` function within *Ghidra*, I finally notice it. There is a constant `0.0` being passed into `printf`.

![image-20251215043724589](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215043724589.png)

Toggling a breakpoint on the `printf` call within *x64dbg* I confirm that `0` is indeed the value being passed in - `RDX` = `0x0000000000000000`.

![image-20251215044047046](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044047046.png)

Modifying `RDX` during execution to `0x99` - decimal 153:

![image-20251215044148408](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044148408.png)

Yields expected and successful results.

![image-20251215044231708](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044231708.png)





---

## 8. Making a Solution

### 8.1 Patching Solution

Since I assume patching is allowed for this *crackme*. Simply modifying the `printf` wrapper to move `0x99` into `[rsp+48]` and replacing the last byte with a `nop` we can have this experience consistently.

![image-20251215044826393](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044826393.png)

![image-20251215044953879](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044953879.png)

Alternatively, instead of patching the `printf` wrapper, one could patch the `xor edx, edx` instruction within `main`. As that is the value that is being passed through to the string formatter `%d`.

![image-20251215045559637](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215045559637.png)



### 8.2 Pushing my Learning - Making a Trainer

As much fun as I had chasing my own tail this entire challenge, I thought the solution was quite ***boring***.
So I challenged myself to make a *Python* script that would request a number from the user, load the *CTF* executable, suspend it upon entry, modify the appropriate bytes in memory, resume execution, and have it display correctly. A proper ***trainer***.

Now that sounds like a fun challenge! First thing is first, I need to obtain a static offset to the `xor` instruction within `main`.

![image-20251215045654459](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215045654459.png)

So it seems that if I add `0x11929` (`0x140011929` - `0x140000000`) to the module base address, that would give me the address that I want to patch. Just to ensure I am correct, I restart execution within *x64dbg* and break on the *Entry Breakpoint*, go into the *Memory Map*, and find the address of the *PE* - `0x00007FF6D87A0000`.

![image-20251215050013706](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215050013706.png)

`0x00007FF6D87A0000` + `0x11929` = `0x7FF6D87B1929`.
If I resume execution and get back to my breakpoint in `main`, the `xor` instruction ***SHOULD*** be `0x7FF6D87B1929`.

![image-20251215050306185](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215050306185.png)

Sanity check completed successfully!



#### 8.2.1 Replacing `XOR` with a `MOV`

Let's get to programming the ***trainer***.

In reverse-engineering / game hacking, a *trainer* is a small helper program that *attaches to (or launches)* a target process and modifies its memory at runtime to change behaviour without permanently changing the executable on disk.

```python
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
PATCH_RVA = 0x11929  # where to write (RVA)
EDX_VALUE = 99  # imm32 for `mov edx, imm32`

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
    if not K32.CreateProcessW(wt.LPCWSTR(str(exe)), cmd, None, None, False, 0x00000004, None, None, ctypes.byref(si), ctypes.byref(pi)):  # 0x00000004 = CREATE_SUSPENDED
        die("CreateProcessW(CREATE_SUSPENDED) failed")
    return int(pi.dwProcessId), int(pi.hProcess), int(pi.hThread)


if __name__ == "__main__":
    exe = Path(EXE_PATH)
    if not exe.is_file():
        print(f"[-] EXE not found: {exe}", file=sys.stderr)
        raise SystemExit(1)

    patch = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32

    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)
        addr = base + PATCH_RVA

        print(f"[+] PID: {pid}")
        print(f"[+] ImageBase: 0x{base:016X}")
        print(f"[+] Patch: RVA 0x{PATCH_RVA:X} -> VA 0x{addr:016X}")
        print(f"[+] Old: {rpm(hproc, addr, len(patch)).hex(' ').upper()}")
        print(f"[+] New: {patch.hex(' ').upper()}  (mov edx, {EDX_VALUE})")

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

```

And it failed...

I did not fully understand that `mov edx, <x>` is *5-bytes* long whilst `xor edx, edx` is *2-bytes long*. My original thought process was that since `xor edx, edx` in byte-code is `31 D2` and `mov edx, 99` in byte-code is `BA 63` I could just replace those two bytes and it would work.
I was wrong.

The `mov` instruction is actually encoded as *5-bytes*. Because the instruction being using is `mov edx, 99`. In *x86-64*, the encoding for `mov r32, imm32` is `B8 + r   <imm32>`.

- `B8` is the base opcode for `mov r32, imm32`.
- `r` is the register number - 0 = `EAX`, 1 = `ECX`, 2 = `EDX`, etc.
- For `EDX` (register index 2) the opcode becomes **`BA`** (`B8 + 2`).
- Then 4-byte immediate value `imm32`.

```
BA 63 00 00 00
^^ ^^^^^^^^^^^
│    └── 4-byte immediate (99 decimal = 0x63, little-endian 63 00 00 00)
└──── opcode “mov edx, imm32”
```

That’s why the instruction is 5 bytes total. *1-byte* opcode (`BA`) + *4-byte* immediate (`63 00 00 00`).



#### 8.2.2 Copying the Rest

To fix this I thought I just had to copy the bytes proceeding the `xor edx, edx` (`31 D2`) all the way to the `ret` instruction (`48 8D 0D CE 16 00 00 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED FC FE FF 31 C0 48 83 C4 28 C3`). Then insert them after my newly added `mov` instruction. ***BUT***, this also would not work. The file already has a fixed sequence of bytes. There is no *free space* between instructions. The bytes for `lea` and `call` are *immediately* after `xor`. If I just insert the extra bytes everything after will move down. This would cause issues:

- `lea rcx, [rip+16CEh]` since its `RIP` relative displacement is now wrong.
- `call printf` / `call scanf` since they’re relative calls, their offsets are now wrong too.



#### 8.2.3 Code Cave Johnson

This presents an ideal time to implement a code cave. For those that are unaware of what a code cave is, here is a quick explanation. A *code cave* is a chunk of unused or padding space inside a program’s executable memory - often a run of `NOP`s or leftover bytes - that you can repurpose to place your own instructions.

In practice, you:

1. *Overwrite* a few bytes at the original code location with a `jmp` to the cave - called a “*trampoline*”.
2. Run your *custom code* inside the cave
3. *Jump back* to the original code flow right after the bytes you overwrote.

Let's get started! Right after the `main` function there appears to be some usable space.

![image-20251215062012817](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215062012817.png)

I decide to use the space right after that lone `jmp` instruction (`0x7FF6D87B1955`). Since we already have an offset to the `xor` instruction - `0x11929` - we just need to increment that offset by `0x2C` (`0x00007FF6D87B1955` - `0x00007FF6D87B1929`), which gives us the result `0x11955` (`0x11929` + `0x2C`).

This is ***AGAIN*** where I realize something. The `jmp` instruction is *5-bytes* long too. So regardless if I use `mov` or `jmp` I will still have the same problem as earlier.

After doing some research, I obtain a better grasp and understanding of what needs to be done.
Here the layout of the `main` function is shown.

```
140011920  48 83 EC 28            sub  rsp,28h          ; 4 bytes
140011924  E8 1E FE FE FF         call __main           ; 5 bytes
140011929  31 D2                  xor edx,edx           ; **2 bytes**
14001192B  48 8D 0D CE 16 00 00   lea rcx,[rip+...fmt]  ; 7 bytes
140011932  E8 A9 FC FE FF         call printf           ; 5 bytes
```

The sizes of both the instructions I tried to use `mov edx, imm32` (`BA xx xx xx xx`) and `jmp rel32` (`E9 xx xx xx xx`) are *5-bytes* long. When trying to assemble either `mov edx,99` or `jmp cave` at the address where `xor edx, edx` used to be, my *Python* script writes *5-bytes* starting at `0x140011929`. Those *5-bytes* overwrite the *2-bytes* of `xor` (`31 D2`) ***PLUS*** the first *3-bytes* of the following `lea` instruction (`48 8D 0D`).

To fix this, after placing in our `jmp` instruction we `NOP` out the remaining *4-bytes*. The logic will look like:

**Original code around the hook:**

```
140011929  31 D2                      ; xor edx, edx
14001192B  48 8D 0D CE 16 00 00       ; lea rcx, [rip+...]
140011932  E8 A9 FC FE FF             ; call printf
```

**We overwrite starting at `0x140011929` with a *5-byte* `jmp cave`:**

```
140011929  E9 xx xx xx xx             ; jmp cave (5 bytes)
14001192E  CE 16 00 00                ; leftover junk from old LEA (bad)
```

 - Those `CE 16 00 00` bytes are now garbage because we cut the old `lea` instruction in half.

**We fix the “junk” by turning it into `NOP` instructions:**

```
140011929  E9 xx xx xx xx             ; jmp cave
14001192E  90                         ; nop
14001192F  90                         ; nop
140011930  90                         ; nop
140011931  90                         ; nop
140011932  E8 A9 FC FE FF             ; call printf (unchanged)
```

The NOPs are just *padding* so the bytes between the `jmp` instruction and the next real instruction are valid instructions *even* if they’re *never* hit.

Execution now flows:

- `sub rsp, 28`
- `call __main`
- **`jmp cave`**
- x4 `NOP`s
- Code cave code runs.
- Code cave returns to address of choice to resume program execution at desired point.



#### 8.2.4 Science Isn’t About Why - It’s About This Code Cave

With my new found knowledge I get to work *making life take the lemons back*!

Some helper functions to make life a bit a little less complicated:

```python
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
```



I begin with creating the byte code for the assembly I am going to be patching in. Starting with the *trampoline* - the `jmp` instruction into the code cave.

```python
PATCH_CAVE = 0x11955 								# offset to where the code cave will be located
addr_cave = base + PATCH_CAVE 						# address to the code cave
patch = jmp_rel32(addr, addr_cave) 					# EB = JMP rel8 (short jump)
patch += b"\x90\x90\x90\x90"						# add the proceeding 4 NOPs
```

Continuing on with the code cave. This is where things start to get a little bit more interesting, due to the `lea` instruction.

```python
# Return after cave: instruction immediately after the 9-byte overwrite.
RETURN_RVA = 0x11932
# printf format string RVA ("Your count points is %d").
PRINTF_FORMAT_RVA = 0x13000
# printf IAT slot RVA (the slot contains the imported function pointer).
PRINTF_IAT_RVA = 0x15DF

addr_return = base + RETURN_RVA  # return VA
addr_str = base + PRINTF_FORMAT_RVA  # printf format string VA
addr_printf_wrapper = base + PRINTF_IAT_RVA  # printf IAT slot VA (contains pointer to printf)

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
```

In *x64*, this `LEA` instruction uses `RIP` relative addressing meaning it computes an address as `RIP` (next instruction) + a *32-bit* displacement and stores that address in the destination register.

Using the `lea` instruction from the `main` function as an example - `48 8D 0D CE 16 00 00`:

- `48` = `REX.W`  - use 64-bit register.

  - In *x64* many instructions can have a *1-byte* `REX` prefix: `0100WRXB` (binary).

  - **W** = “64-bit operand size”.

  - If **REX.W = 1**, the instruction uses 64-bit registers/operands (e.g., `rcx` instead of `ecx`).
    So `48` is a REX prefix where **W=1** (and R/X/B=0). That’s why `48 8D ...` becomes a 64-bit `lea`.

- `8D` = `LEA`

- `0D` = ModRM byte for **reg=RCX** and **rm=RIP-relative** (`mod=00, reg=001, rm=101`)

  - **ModRM** is a 1-byte field used by many x86/x64 instructions to specify:

  - **which register** is involved, and/or
  - **which addressing mode** (register vs memory, plus how to compute the memory address)

  It’s split into 3 bitfields:

  - `mod` (2 bits): addressing form (register vs memory, displacement size)
  - `reg` (3 bits): a register operand (or opcode extension)
  - `rm`  (3 bits): another register OR “memory addressing form”

  For your byte `0D` = `0000 1101`:

  - `mod = 00` (memory, no extra disp except special cases)
  - `reg = 001` (RCX)
  - `rm  = 101` (**RIP-relative** in 64-bit mode when `mod=00`)

- `CE 16 00 00` = `disp32` *little-endian* (`0x000016CE`).
  *x86/x64* stores multi-byte integers in *little-endian* meaning *least significant byte first* (the “small end” first).

Notice `disp32` is only *4-bytes* long. The instruction only has room for a *32-bit* displacement (*4-bytes*) and not an *8-byte* absolute address. Meaning the instruction format can’t store a full *64-bit* address. This is done on purpose for a few reasons:

- Keeps instructions smaller, *7-bytes* instead of 10+.
- It makes code *position-independent - executable/code* (*PIE/PIC*): the module can be loaded at different base addresses (*ASLR*), and the code still finds its data because it’s using “distance from here” rather than a hardcoded absolute address.
- Lets the compiler reference nearby data in `.rdata` efficiently.
- In *x64*, you can’t encode a simple `mov rcx, [imm64]` memory operand like in some *x86* patterns; `RIP` relative is the normal way to reference globals/strings.

So whenever you relocate `RIP` relative instructions, you ***MUST*** recompute `disp32`. Remember `RIP` relative addressing uses `RIP` of the ***NEXT*** instruction, ***NOT*** the current one.

In *x64* `lea rcx, [rip + disp32]` is *defined* as:
\[
RCX = RIP_{\text{next}} + disp32
\]

Since
\[
RIP_{next} = INSTRUCTION_{address} + INSTRUCTION_{length}
\]
Substitute into the first equation:
\[
RCX = (INSTRUCTION_{address} + INSTRUCTION_{length}) + disp32
\]

Solving for `disp32`:
\[
disp32 = RCX - (INSTRUCTION_{address} + INSTRUCTION_{length})
\]

If the goal is for `RCX` to equal the target address, IE: \(RCX = \text{target}\), then:
\[
disp32 = TARGET_{address} - (INSTRUCTION_{address} + INSTRUCTION_{length})
\]


Running the *Python* script produces the following results:

```bash
$ py ./simple_trainer.py 
[+] PID:        6684
[+] ImageBase:   0x00007FF6D87A0000
[+] PatchSite:   RVA 0x11929 -> VA 0x00007FF6D87B1929
[+] CodeCave:    RVA 0x11955 -> VA 0x00007FF6D87B1955
[+] Return:      RVA 0x11932 -> VA 0x00007FF6D87B1932
[+] FormatStr:   RVA 0x13000 -> VA 0x00007FF6D87B3000
[+] PrintF:      RVA 0x15DF -> VA 0x00007FF6D87A15DF
[+] EDX_VALUE:   99
[+] Trampoline (9 bytes):
    Old: 31 D2 48 8D 0D CE 16 00 00
    New: E9 27 00 00 00 90 90 90 90
[+] CodeCave stub (33 bytes):
    Old: 90 90 90 90 90 90 90 90 90 90 90 FF FF FF FF FF FF FF FF 50 19 7B D8 F6 7F 00 00 00 00 00 00 00 00
    New: BA 63 00 00 00 48 B9 00 30 7B D8 F6 7F 00 00 48 83 EC 28 E8 73 FC FE FF 48 83 C4 28 E9 BC FF FF FF
[+] Writing code cave stub...
[+] Writing trampoline...
[+] Sanity check (still suspended): sleeping 0.25s then re-reading patch sites...
[+] PatchSite intact: True
[+] CodeCave intact:  True
[+] Dumping bytes: base+0x11920 -> base+0x11976 (87 bytes)
    0x00007FF6D87B1920: 48 83 EC 28 E8 1E FE FE FF E9 27 00 00 00 90 90
    0x00007FF6D87B1930: 90 90 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED
    0x00007FF6D87B1940: FC FE FF 31 C0 48 83 C4 28 C3 90 90 90 90 90 90
    0x00007FF6D87B1950: E9 6B FC FE FF BA 63 00 00 00 48 B9 00 30 7B D8
    0x00007FF6D87B1960: F6 7F 00 00 48 83 EC 28 E8 73 FC FE FF 48 83 C4
    0x00007FF6D87B1970: 28 E9 BC FF FF FF 00
[+] Sanity check passed; resuming.


```

Strange... There is no output.
For a sanity check - I copy the bytes for the *trampoline* and the *code cave stub*  into *x64dbg*, editing the bytes while broken on the start of the `main` function.

![image-20251215234603563](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215234603563.png)

I then resume program execution - from *x64dbg*.

![image-20251215234648478](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215234648478.png)

We get somewhat of the expected result. I realize here that the `jmp` out of the *code cave* is going to the wrong address. That is why the string was output twice to console. Although, this doesn't seem to clear any confusion with why my *Python* script isn't working. It appears to be doing the same exact byte code manipulation that I ***just saw working***.

To fix the return bug I adjust `RETURN_RVA` from `0x11932` to `0x11937`. This should land us on the correct return address now.
As for the reason it's not executing correctly when ran through my *Python* trainer, I am unsure of.



##### 8.2.4.1 Who is Ready to Make Some Bugs

I realize I am breaking the *Win64 Calling Convention* by doing `sub rsp, 0x28` inside the *code cave*. I remove the bytes I added for the `add` and `sub` instructions. The *prologue* to `main` already allocates *shadow space* (`0x20`) and fixes alignment. So at the *code cave* `RSP` is already in the correct state for calls.

After a ***LOT*** of debugging, testing, and failure I finally get the result I want. I was having issue after issue due to the memory space that I selected for my code cave. I thought that the space I had chosen for the *code cave* was free and not being used. After much debugging it seemed that it was holding some kind of data, maybe a pointer. It could be an address that is being loaded during runtime which would explain

I figured this out since whenever I would ***ONLY*** patch the `xor` instruction in `main` there would be no problem. *BUT*, if I added the code cave itself it would never even get to the `main` instruction. It seemed to crashed before ever hitting it.

The worst part during debugging was that when I would modify the bytes - with the bytes provided by my *Python* script - within *x64dbg* I would see the functionality that I was expecting. I believe this is because the memory space I was overwriting was used during some start-up sequence. So when I modified the memory space with execution paused on the start of `main` it had no effect.

Patching in *x64dbg* worked because the program was already initialized and the debugger can mask memory-protection issues. My trainer patched a process before initialization. Allocating memory with `VirtualAllocEx` fixed it by providing a guaranteed writable region that isn’t affected by *PE* section protections.

Old approach - code cave at RVA `0x11955` was overwriting bytes inside the module’s `.text` section assuming they were padding. This caused a break in unrelated logic and would error out `0xC0000005` before the trampoline ever ran.

New approach - real code cave via `VirtualAllocEx`: Place the code cave stub in a fresh, private *RWX* page owned by the process. No longer corrupting the module’s code/data, so the only behaviour change should be the one intentionally introduced (the *trampoline* jump).

`VirtualQueryEx` = Tell me what’s already there.
 It **doesn’t change anything**. It only **inspects** a memory region in the remote process and reports details like:

- region base address
- region size
- state (`MEM_COMMIT` / `MEM_RESERVE` / `MEM_FREE`)
- protection (`PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_GUARD`, `PAGE_NOACCESS`, etc.)

Use it when trying to answer: “Is `addr_flag` actually writable?”, “What memory page does this address live in?”, “Is this address even committed?”.

`VirtualAllocEx` = Give me new memory.
 It *does change memory*. It *allocates fresh pages* inside the remote process, and you get to choose protections.

Use it when you want: a guaranteed *RW* scratch area for a flag byte, a safe buffer for strings / shellcode / *trampolines*, the stop guessing about *RVAs* and section permissions option

Both should be used in this order:

1. `VirtualQueryEx` - *diagnose your current `addr_flag`*
    If it reports “not writable” (or it has `GUARD` / `NOACCESS`), then your write will crash. No mystery.
2. `VirtualAllocEx` - *avoid the problem entirely*
    Allocate a small **RW** page, store the flag there, and point your cave/trampoline at it. This is the “always works” approach.



Finally, the moment I have been waiting for!

```bash
$ py ./simple_trainer.py 
[+] PID:         27512
[+] ImageBase:   0x00007FF6D87A0000
[+] PatchSite:   RVA 0x11929 -> VA 0x00007FF6D87B1929
[+] CodeCave:    VA  0x00007FF6D87C0000  (VirtualAllocEx)
[+] Return:      RVA 0x11937 -> VA 0x00007FF6D87B1937
[+] FormatStr:   RVA 0x13000 -> VA 0x00007FF6D87B3000
[+] PrintF:      RVA 0x15E0  -> VA 0x00007FF6D87A15E0
[+] Dumping bytes: base+0x11920 -> base+0x11945 (38 bytes)
    0x00007FF6D87B1920: 48 83 EC 28 E8 1E FE FE FF 31 D2 48 8D 0D CE 16
    0x00007FF6D87B1930: 00 00 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED
    0x00007FF6D87B1940: FC FE FF 31 C0 48
[+] Dumping bytes: base+0x11920 -> base+0x11945 (38 bytes)
    0x00007FF6D87B1920: 48 83 EC 28 E8 1E FE FE FF E9 D2 E6 00 00 90 90
    0x00007FF6D87B1930: 90 90 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED
    0x00007FF6D87B1940: FC FE FF 31 C0 48
[+] Trampoline (9 bytes):
    Old: 31 D2 48 8D 0D CE 16 00 00
    New: E9 D2 E6 00 00 90 90 90 90
[+] CodeCave Stub (25 bytes):
    Old: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    New: BA 63 00 00 00 48 B9 00 30 7B D8 F6 7F 00 00 E8 CC 15 FE FF E9 1E 19 FF FF
[+] Resuming.
Your count points is 99
```

Boy, does it feel good!



Time to clean up the code and extend it's functionality a bit. All *Python* files will be included alongside the solution write up. In the *trainerlib* folder you will find a few helper files I have created. `trainer.py` houses the new version that accepts command line arguement inputs, while `simple_trainer.py` is a more bare bones example that uses a hard coded value.

Running `trainer.py`:

- ```bash
  py ./trainer.py --edx 1337
  ```

  - ```bash
    $ py ./trainer.py --edx 1337
    [+] PID:         27480
    [+] ImageBase:   0x00007FF6D87A0000
    [+] PatchSite:   RVA 0x11929 -> VA 0x00007FF6D87B1929
    [+] CodeCave:    VA  0x00007FF6D87C0000  (VirtualAllocEx)
    [+] Return:      RVA 0x11937 -> VA 0x00007FF6D87B1937
    [+] FormatStr:   RVA 0x13000 -> VA 0x00007FF6D87B3000
    [+] PrintF:      RVA 0x15E0  -> VA 0x00007FF6D87A15E0
    [+] EDX_VALUE:   1337
    [+] Dumping bytes: base+0x11920 -> base+0x11945 (38 bytes)
        0x00007FF6D87B1920: 48 83 EC 28 E8 1E FE FE FF 31 D2 48 8D 0D CE 16
        0x00007FF6D87B1930: 00 00 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED
        0x00007FF6D87B1940: FC FE FF 31 C0 48
    [+] Dumping bytes: base+0x11920 -> base+0x11945 (38 bytes)
        0x00007FF6D87B1920: 48 83 EC 28 E8 1E FE FE FF E9 D2 E6 00 00 90 90
        0x00007FF6D87B1930: 90 90 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED
        0x00007FF6D87B1940: FC FE FF 31 C0 48
    [+] Trampoline (9 bytes):
        Old: 31 D2 48 8D 0D CE 16 00 00
        New: E9 D2 E6 00 00 90 90 90 90
    [+] CodeCave Stub (25 bytes):
        Old: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        New: BA 39 05 00 00 48 B9 00 30 7B D8 F6 7F 00 00 E8 CC 15 FE FF E9 1E 19 FF FF
    [+] Resuming.
    Your count points is 1337
    ```

- ```bash
  py ./trainer.py --edx 53110 --quiet
  ```

  - ```bash
    $ py ./trainer.py --edx 53110 --quiet
    Your count points is 53110
    ```

Ranges that can be *encoded*: `0x0` to `0xFFFFFFFF` (*32-bit*). Which means that the highest number that the `points` can be is `2,147,483,647`. This is due to the value being interpreted as a *signed 32-bit integer*. If it was an *unsigned 32-bit integer*, the highest value would have been `4,294,967,295`.

![image-20251217055139992](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251217055139992.png)

Anything above this number will cause the integer to overflow and become negative.

![image-20251217055425779](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251217055425779.png)



---

## 9. Conclusion

When I first started this challenge I assumed that this challenge would be a hidden “correct” points value and some validation logic inside the binary. I therefore started looking for comparisons, success/fail messages, and any functions using the `POINTS` global.

**Correction:** The symbol at `0x140013018` is not a global integer at all, it’s the `"Your count points is %d"` *format string* in `.rdata`. Renaming it to something like `PRINTF_FMT` is more accurate. The real “points” value is the integer argument being passed into `printf` (in `EDX`), which is being forced to 0 in `main`.

After fully enumerating the functions in Ghidra and inspecting the entry point (`mainCRTStartup`), `__tmainCRTStartup`, and `main`, I found that the only user code is:

```c
int POINTS;  // global, default 0

int main(void) {
    __main();  // CRT initialization
    printf("Your count points is %d", POINTS);
    scanf("%d", &POINTS);
    return 0;
}
```

There are no additional functions that read or compare `POINTS`, no hidden success strings, and no conditional branches based on the user’s input. The program simply prints the current value of a global integer (which starts at 0), reads a new value from stdin, and exits.

Reading the comments on the challenge clarified the author’s intent: the goal is not to discover a secret value, but rather to **manipulate the program or its data so that it reports points greater than zero**.

The cleanest “author-intended” solve is to patch the instruction that forces the printed value to 0. In `main`, the program executes `xor edx, edx` immediately before loading the format string and calling `printf`. Since `EDX` is the 2nd argument register on *Win64*, this guarantees the printed number is always 0.

To solve it permanently on disk, I replaced that behaviour so `EDX` becomes non-zero before the `printf` call. One approach is:
- Overwrite the bytes starting at the `xor edx, edx` site with a 5-byte instruction that sets `EDX` to a constant (e.g., `mov edx, 99`),
- And pad any overwritten leftover bytes with `NOP`s so the next real instruction boundary remains valid.

After patching, the binary consistently prints a `points` value greater than zero without requiring a debugger.

To push my learning, I built a *Python* trainer that launches the process suspended, finds the module base (*ASLR*-safe), and installs a *trampoline* that redirects execution into a custom *code cave* stub.

The main technical lessons were:

- **Instruction size matters:** `xor edx, edx` is 2 bytes, but `mov edx, imm32` and `jmp rel32` are 5 bytes. Writing 5 bytes over a 2-byte instruction will clobber neighboring instructions unless you intentionally pad and/or relocate execution.
- **RIP-relative code must be treated carefully:** relocating code that uses `RIP` relative addressing (`LEA`/`CALL`/`JMP` patterns) requires recomputing displacements, otherwise it will reference the wrong targets.
- **Memory timing/protection is real:** my initial “code cave inside the module” assumption was wrong. That region wasn’t safely unused in the way I assumed, and patching *before initialization* caused crashes. Using `VirtualAllocEx` gave me a guaranteed safe RWX region for the stub, which made the trainer reliable.

In the end, I solved the crackme both ways: the straightforward patch (expected) and a fully runtime-based trainer (hard mode). The trainer took longer, but it forced me to internalize *Win64* calling conventions, patch sizing, *trampolines/code caves,* *ASLR*-safe addressing, and real-world memory constraints. Which is exactly the kind of practical knowledge I want from these challenges.

