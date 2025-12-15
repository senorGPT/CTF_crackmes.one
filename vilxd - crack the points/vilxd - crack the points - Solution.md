# Vilxd - Crack the Points — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/690fa2f12d267f28f69b7c44  
**Author:** *vilxd*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.0 | 3.5 | x86-64 | C/C++ |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\vilxd - crack the points\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** WIP  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]

---

## 1. Executive Summary

This document captures my reverse-engineering process for the crackme `crack the points` by `vilxd`. The target appears to be a simple command line process that prompts the user for a password.

I successfully:

- Performed basic static reconnaissance.
- Surveyed imports. Confirmed there appears to be ***NO*** anti-debugging measures.
- Tried to locate strings associated with console outputs.
  - TODO



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
- Architecture:
- Compiler hints:
- Packing/obfuscation signs:



### 4.2 Imports / Exports

![image-20251213020857175](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213020857175.png)

Hypotheses:
- File I/O?
- Crypto?
- Anti-debug?



#### 4.2.1 KERNEL32.DLL

![image-20251213020921851](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213020921851.png)



#### 4.2.2 msvcrt.dll

<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213021022160.png" alt="image-20251213021022160" style="zoom:67%;" />

<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213021035547.png" alt="image-20251213021035547" style="zoom:67%;" />



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x64dbg* yields no immediate or obvious signs of anti-debugging logic.



### 5.2 String Driven-Entry 

Searching for string references within the target *Portable Executable* (*PE*) yields results.

![image-20251213025131959](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213025131959.png)



Double clicking on the string reference for "*Your count points is %d*" brings me into the disassembly view where I start to poke and prod around. I land on some function and add a breakpoint before the first `call` instruction and restart program execution.

![image-20251213025954546](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213025954546.png)

I trace the logic out of the function and land within what appears to be the `main` function?

![image-20251213031207130](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213031207130.png)

Restarting program execution and going back into that first function I notice that after the second `call` instruction the string is output to console. I proceed to step into that function.

![image-20251213030159338](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213030159338.png)

Tracing the input logic through stepping through yields little results. For some reason being difficult to find the comparison logic, yet the `main` function logic seems simple. I believe this has to do with the `scanf` wrapper it is utilizing - or I assume it is - to grab the user input.



## 6. Static Binary Analysis - Ghidra

I guess it is a good of time as any to learn a new tool, `Ghidra`.

*Ghidra* is a free open-source reverse-engineering suite created by the U.S. *National Security Agency* (*NSA*). It’s designed to analyse compiled binaries - EXEs, DLLs, firmware - without running them, using static analysis. In practice that means *Ghidra* takes raw machine code and reconstructs it into human-readable assembly and even *C-like* pseudocode.

Where a debugger like *x64dbg* shows "what the program is doing right now", `Ghidra` focuses on *how the program is built*:

- It identifies functions, cross-references, code vs data, and control flow.
- It has a built-in decompiler that can turn many functions into *C-style* pseudocode.
- It lets you rename functions and variables, add comments, define structs, and track how data flows through the program.

This makes it especially useful for understanding complex logic that would be painful to follow step-by-step in a live debugger such as:

- Custom serialization or parsing code
- Obfuscated control flow
- Large state machines
- Library or runtime internals (*scanf/strtol*, *CRT* start-up, etc.)



#### 6.1 Ghidra - String-Driven Entry

I use the `Defined Strings` *Window* shortcut to bring up the found string references.

![image-20251215001522379](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215001522379.png)

![image-20251214232946534](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251214232946534.png)

Once again targeting the `Your count points is %d` string. Double clicking it brings me to where the string definition lives.

![image-20251215001210481](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215001210481.png)

On the right in green text we can see three *cross references* (*XREFS*); `1400001e4`, `printf.constprop.0:14000160c`, and `main:14001192b`. Focusing on the `main` reference, I double click it which brings me to the function logic. My assumption from earlier was correct regarding the `main` function logic,  this assembly matches that of the assembly discovered within [x64dbg](###5.2 String Driven-Entry). Albeit, with some more information thanks to *Ghidra*.

![image-20251215004802416](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215004802416.png)

One of *Ghidra's* superpowers is that it comes with a built-in *decompiler* which turns the *assembly* into *C-like pseudo code*. *Clicking on the `main` function* - *Window* - *Decompile: main*; This opens open a window with the pseudo code.

![image-20251215005714226](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215005714226.png)

This makes it clear that `DAT_140013018` represents the `points`. Let's go ahead and rename it. *Right clicking `DAT_140013018`* - *Edit Label*; I change it to `POINTS`. Now with a more human readable name, it should be a easier to spot and trace when looking at the assembly / pseudo code.
The `main` function just prints the prompt, reads an integer into a global, and exits.

*Right clicking `POINTS`* - *References* - *Show References* to Points (shortcut: *CTRL + SHIFT + F*); Opens a window with all references to the `POINTS` variable.

![image-20251215010845947](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215010845947.png)

The second reference `LEA _Argc, [POINTS]` is the instruction from the `main` function we just came from so I ignore it. Clicking on the first reference brings us into another function, which again we aren't seeing for the first time- the wrapper around the `scanf` function.

![image-20251215014932508](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215014932508.png)

 

The confusion from earlier is more clear here. The only two references to the global `POINTS` variable are from the `main` and `scanf` functions. This begs the question, ***where is the comparison logic?***
I am starting to wonder if there is another function that is *indirectly* accessing the `POINTS` variable or utilizing a *return value* from some kind of helper/wrapper function.



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
- Any way you achieve that (editing the global, patching *printf*, changing the string) is considered a “solve”.



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

With that in mind. what we want is the address within `RDX` as that is the variable that is being used with `%d`. *BUT*, the problem here is that `RDX` will be dynamic - IE, on the next subsequent run it will not be `000001BC238A0000` but point to a different address.

![image-20251215040656935](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215040656935.png)



#### 7.1.1 Finding a Static Offset

Going back to *Ghidra*, I double click on the `POINTS` variable which brings me to it's definition.

![image-20251215041453302](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215041453302.png)

I can see that the address of `POINTS` is `0x140013018`. *Ghidra’s* addresses start the image at **`0x140000000`**. So `0x140013018` is `0x13018` bytes *after* the image base. That `0x13018` is the *Relative Virtual Address* (*RVA*). *Address Space Layout Randomization* (*ASLR*) will move the whole module at runtime, but the *RVA* stays constant. So we can treat `0x13018` as the static offset to the read-only data.

This is where I realize I have made a mistake. I was mixing up things from *x64dbg* and *Ghidra*. The address above in *Ghidra* is the format string, not the actual `POINTS` variable. That’s why it lives in `.rdata` and is read-only. I have been chasing another red-herring.

Occam's Razor is a problem-solving principle that states when faced with competing explanations, the simplest one is usually the best.
Going back into the `main` function within *Ghidra*, I finally notice it. There is a constant `0.0` being passed into `printf`.

![image-20251215043724589](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215043724589.png)

Toggling a breakpoint on the `printf` call within *x64dbg* I confirm that `0` is indeed the value being passed in.

![image-20251215044047046](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044047046.png)

Modifying `RDX` during execution to `0x99` (153)

![image-20251215044148408](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044148408.png)

Yields expected and successful results.

![image-20251215044231708](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044231708.png)





---

## 8. Making a Solution

### 8.1 Patching Solution

Since I assume patching is allowed for this *crackme*. Simply modifying the `printf` wrapper to move `0x99` into `[rsp+48]` and replacing the last byte with a `nop` we can have this experience consistently.

![image-20251215044826393](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044826393.png)

![image-20251215044953879](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215044953879.png)

Alternatively, instead of patching the `printf` wrapper, one could patch the `xor edx, edx` instruction within `main`. As that is the value that is being passed through.

![image-20251215045559637](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215045559637.png)



### 8.2 Learning Something More

As much fun as I had chasing my own tail this entire challenge, I thought the solution was quite boring.
So I challenged myself to make a simple *Python* script that would request a number from the user, load the *CTF* executable, pause it, modify the appropriate bytes in memory, resume execution, and have it display correctly.

Now that sounds like a fun challenge! First thing is first, I need to obtain a static offset to `xor` instruction within `main`.

![image-20251215045654459](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215045654459.png)

So it seems that if I add `0x11929` (`0x140011929` - `0x140000000`) to the module base address, that would give me the address that I want to patch. Just to ensure I am correct, I restart execution within *x64dbg* and break on the *Entry Breakpoint*, go into the *Memory Map*, and find the address of the *PE* - `0x00007FF6D87A0000`.

![image-20251215050013706](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215050013706.png)

`0x00007FF6D87A0000` + `0x11929` = `0x7FF6D87B1929`.
If I resume execution and get back to my breakpoint in `main`, the `xor` instruction ***SHOULD*** be `0x7FF6D87B1929`.

![image-20251215050306185](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215050306185.png)

Sanity check completed successfully!



#### 8.2.1 Replacing `XOR` with a `MOV`

Let's get to programming the trainer.

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

I was wrong. the `mov` instruction is actually encoded as *5-bytes*. Because the instruction being using is `mov edx, 99`. In *x86-64*, the encoding for `mov r32, imm32` is `B8 + r   <imm32>`.

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

To fix this I thought I have to copy the bytes proceeding the `xor edx, edx` (`31 D2`) all the way to the `ret` instruction (`48 8D 0D CE 16 00 00 E8 A9 FC FE FF 48 8D 0D DA 16 00 00 E8 ED FC FE FF 31 C0 48 83 C4 28 C3`) and insert them after my newly added `mov` instruction. ***BUT***, this also would not work. The file already has a fixed sequence of bytes. There is no *free space* between instructions. The bytes for `lea` and `call` are *immediately* after `xor`. If I just insert the extra bytes everything after will move down. This would cause issues:

- `lea rcx, [rip+16CEh]` since its `RIP`-relative displacement is now wrong.
- `call printf` / `call scanf` since they’re relative calls, their offsets are now wrong too.



#### 8.2.3 Code Cave Johnson

This presents an ideal time to implement a code cave. (EXPLAIN WHAT A CODE CAVE IS HERE)

Right after the `main` function there appears to be some usable space.

![image-20251215062012817](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215062012817.png)

I decide to use the space right after that lone `jmp` instruction (`0x7FF6D87B1955`). Since we already have an offset to the `xor` instruction - `0x11929` - we just need to increment that offset by `0x2C` (`0x00007FF6D87B1955` - `0x00007FF6D87B1929`), which gives us the result `0x11955` (`0x11929` + `0x2C`).

This is where ***AGAIN*** I realize something. the `jmp` instruction is too *5-bytes* long, so regardless if I use `mov` or `jmp` I will still have the same problem.

After doing some research, I get a better grasp of what I need to do.
Here the layout of the `main` function is shown.

```
140011920  48 83 EC 28            sub  rsp,28h          ; 4 bytes
140011924  E8 1E FE FE FF         call __main           ; 5 bytes
140011929  31 D2                  xor edx,edx           ; **2 bytes**
14001192B  48 8D 0D CE 16 00 00   lea rcx,[rip+...fmt]  ; 7 bytes
140011932  E8 A9 FC FE FF         call printf           ; 5 bytes
```

The sizes of both the instructions I tried to use `mov edx, imm32` (`BA xx xx xx xx`) and `jmp rel32` (`E9 xx xx xx xx`) are both *5-bytes* long. So when trying to assemble either `mov edx,99` or `jmp cave` at the address where `xor edx, edx` used to be, my *Python* script writes *5-bytes* starting at `0x140011929`. Those *5-bytes* overwrite the *2-bytes* of `xor` (`31 D2`) ***PLUS*** the first *3-bytes* of the following `lea` instruction (`48 8D 0D`).

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



Why this is safe:

- Execution now flows:
  - `sub rsp,28`
  - `call __main`
  - → **`jmp cave`**
  - (it never executes the 4 NOPs)
  - cave code runs
  - cave does `jmp 140011932` (or wherever you want to resume)
- The NOPs are just **padding** so the bytes between the `jmp` and the next real instruction are valid instructions (even if they’re never hit).



#### 8.2.4 Science Isn’t About Why - It’s About This Code Cave





---

## 9. Conclusion

At first I assumed this meant there would be a hidden “correct” points value and some validation logic inside the binary. I therefore started looking for comparisons, success/fail messages, and any functions using the `POINTS` global.

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

Reading the comments on the challenge clarified the author’s intent: the goal is not to discover a secret value, but rather to **manipulate the program or its data so that it reports points greater than zero**. Other solvers achieved this by patching the format string, modifying the immediate value passed to `printf`, or editing the global variable in memory with a debugger.

TODO: something about a simple patch here

To get a static offset suitable for a trainer, I located the instruction in `main` that zeroed EAX just before calling `printf.constprop.0` (the hard-coded points value). In Ghidra that instruction lives at `0x14001193C` and the module image base is `0x140000000`, so the RVA is `0x1193C`. At runtime I can compute the patch address as `moduleBase + 0x1193C` and overwrite the instruction bytes via `WriteProcessMemory`, replacing `xor eax,eax` with `mov eax, <non-zero value>`.

