# <Biglsim04 _ puzzle>

# Biglsim04's puzzle — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/691de1d12d267f28f69b7f16  
**Author:** *Biglsim04*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer, Detect It Easy (DIE), x64dbg*  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.5 | 3.5 | x86-64 | C/C++ |

---

## ![cover](C:\Users\david\Desktop\crackmes.one\Biglsim04 - puzzle\cover.png)

> **Status:** WIP  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]



---

## 1. Executive Summary

This document captures my reverse-engineering process for the crackme `puzzle` by `Biglsim04`. The target appears to be a simple command line process that prompts the user for a password.

I successfully:

- Performed basic static reconnaissance.

- Surveyed imports. Confirmed there appears to be anti-debugging measures.

- Located strings associated with success & failure dialogs. Begun stepping into the key-check path.

  

---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs: Enter password
- Outputs: Access Denied, Access Accepted (assumption based on string references in x64dbg).

### 2.2 Screens

#### 2.2.1 Start-up

![image-20251207213152885](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251207213152885.png)



#### 2.2.2 Failure case

Followed by exit on next key input.

![image-20251208082645518](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208082645518.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*

- Debugger: *x64dbg*

- Static tools: *CFF Explorer, Detect It Easy (DIE)*

  

---

## 4. Static Recon

### 4.1 File & Headers

There appears to be no obvious signs of packing or obfuscation. The classic, boring set of sections `.text, .rdata, .data, .reloc` represent a very typical layout for an unprotected Visual Studio type Portable Executable (*PE*).
The sizes also seem reasonable for a small console application.

![image-20251208085118755](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085118755.png)

Packed binaries often show one or more of these red flags:

- Weird section names:
  `.UPX0, .UPX1, .aspack, .petite`, or just random gibberish.

- Very few sections:
  Sometimes just one or two suspicious ones.

- Abnormal size balance:
  A tiny `.text` with a huge other section holding compressed payload.

It is *IMPORTANT* to note that headers alone can not alone confirm if the *PE* has been packed or obfuscated as the packer/obfuscator might use normal looking section names, keep a standard layout, and/or hide the real tell in entropy or runtime behaviour.



### 4.2 Entropy

Entropy is a measure of how *random-looking* the bytes are in a section.

- Low entropy = looks like normal code/data (more patterns, more repetition).
- High entropy = looks compressed or encrypted (more random).

Why this matters:

- Packed or encrypted payloads often have high entropy.
- Normal .text code usually has moderate entropy.

Rule of thumb (quick reference, not 100%):

- ~6.0–7.2 = often normalish

- ~7.4–8.0 = suspicious for compression/encryption

  

Unfortunately, *CFF Explorer* does not have an entropy viewer so I switch to *DIE*.

![image-20251209031847854](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209031847854.png)

The top blue bar shows *DIE*'s overall heuristic guess based mostly on entropy patterns and layout, not necessarily proof but a strong hint that this is not classically packed.

The table shows each row as a region - header + each *PE* section - with an entropy score.

| Section Name | Entropy Score | Note                                                         |
| ------------ | ------------- | ------------------------------------------------------------ |
| *PE* Header  | 2.51659       | Low entropy is normal for headers.                           |
| .text        | 6.44770       | normal-looking code entropy. If this was packed or encrypted the value would be closer to ~7.5–8.0. |
| .rdata       | 4.66111       | Normal for constants/strings/tables.                         |
| .data        | 2.64577       | Very normal (initialized globals).                           |
| .reloc       | 5.29263       | Also not unusual.                                            |

Nothing here also seems to scream that this *PE* is packed.

Finally, the graph represents a rolling entropy line across the file from start to end. The long flatish area around *~6* matches the `.text` region.
The later dips/spikes reflect transitions into `.rdata`, `.data`, `.reloc`.

Again, if this *PE* was packed the graph would have a big chunk of the line hovering around *~7.4-8*.



### 4.3 Build & Toolchain Information

Summary provided by *DIE*

![image-20251209030922816](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209030922816.png)

**Operation system: Windows(Vista)AMD64, 64-bit, Console**
The binary is a *64-bit Windows console app*. The *Vista* part usually reflects the *minimum subsystem version* or tool heuristics and not that it only runs on Vista.

**Linker: Microsoft Linker (14.36.34123)**
The exact *MSVC linker version* used to produce the EXE.

**Compiler: Microsoft Visual C/C++ (19.36.34123) [LTCG/C]**
Identifies the *Visual C++ compiler version*.
**LTCG** = *Link-Time Code Generation* (whole-program optimization). The `/C` part is just the tool’s way of labelling the language/compile family.

**Language: C**
The tool’s best guess for source language. In practice, this likely means *C or C++* with a C-like signature.

**Tool: Visual Studio(2022, v17.6)**
Maps those version numbers to the likely *IDE/toolchain family* that was used to build the *EXE*.



### 4.4 Imports / Exports

Since it is a simple console application, the only import *SEEMS* to be `KERNEL32.dll`.

|<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085207040.png" alt="image-20251208085207040" style="zoom: 50%;" /> | <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085248818.png" alt="image-20251208085248818" style="zoom: 50%;" /> | <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085310279.png" alt="image-20251208085310279" style="zoom: 50%;" />



Off the bat I notice at least one *VERY* interesting function that is commonly used as a direct check for anti-debugging, `IsDebuggerPresent`.

Other functions that caught my eye are the timing functions; `QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64`, `GetSystemTimeAsFileTime`. These aren't necessarily indicative of anything, but *COULD* be used to support debugger detection logic by performing timing checks.

`GetCurrentProcessId`, `GetStartupInfoW`, and `GetCurrentThreadId` *COULD* also be used as anti-debug logic to check for certain flags or conditions on the program itself.

`LoadLibraryExW`, `GetProcAddress` and `FreeLibrary` could be used to hide libraries/modules by dynamic resolution.

`GetLastError`, `SetLastError`, `RaiseException`, `UnhandledExceptionFilter`, and `SetUnhandledExceptionFilter` could all be used in exception based anti-debugging measures.

`IsProcessorFeaturePresent` is also interesting as it could be used for certain anti-debug exception tricks.

`VirtualProtect` is often used for unpacking, self-modifying code, patching stubs, and flipping page protections around anti-debug regions. 

Some additional functions that are not in the import table from `KERNEL32.dll` that might be worth adding breakpoints to are; `CheckRemoteDebuggerPresent`, ` OutputDebugStringA/W`, `NtQueryInformationProcess`

Furthermore, adding breakpoints on `NTDLL.DLL` functions that are used for anti-debug logic just in case; `NtQueryInformationProcess`, `NtSetInformationThread`, and `RtlAddVectoredExceptionHandler` / `RtlRemoveVectoredExceptionHandler`.



---

## 5. Dynamic Analysis

### 5.1 String-Driven Entry

Starting the program in *x64dbg* to see if any immediate anti-debug code triggers yields nothing, yet...

As always, my first point of attack is a string-driven entry. Searching for string references in *x64dbg* yields the following results:
(Specifically looking for strings that I observed during [start-up](####Start-up) and [failure case](####Failure case); `Hello World!`, `Enter password:`, and `Access Denied!`)

![image-20251209012444569](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209012444569.png)

![image-20251209012459312](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209012459312.png)

That's a lot of references! Utilizing the search functionality at the bottom of the `References` tab will help make searching for the desired string references a breeze.

![image-20251209012604476](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209012604476.png)

Nada! Well that's a first for me. Never before have I had it where there are zero string references found. Something new is always interesting!

Time to switch to a breakpoint approach.



### 5.2 Break-it down-point Time

#### 5.2.1 Anti-Debugging Breakpoints

Before I start adding breakpoints trying to trace any flag related logic, I first want to see where and how some of the functions for anti-debugging measures are being used.

| Function                         | Reason for Interest                                          |
| -------------------------------- | ------------------------------------------------------------ |
| `IsDebuggerPresent`              | The simplest direct debugger check; breaking here often shows the exact branch that decides the *good* vs *bad* branch paths. |
| `SetUnhandledExceptionFilter`    | Programs use this to install custom crash/exception handling; it’s commonly part of exception-based anti-debug tricks. |
| `UnhandledExceptionFilter`       | Often hit when the program deliberately triggers an exception; breaking here helps you see whether the exception flow is being used as a debugger test. |
| `RaiseException`                 | A strong indicator of intentional exception-based detection; it usually marks the start of an anti-debug probe. |
| `QueryPerformanceCounter`        | Used for high-resolution timing checks; stepping/breakpoints can cause delays that the program detects. |
| `GetTickCount`, `GetTickCount64` | Lower-resolution timing checks; still commonly used to detect “debugger slowdowns” around sensitive code blocks. |
| `VirtualProtect`                 | Frequently used for unpacking or self-modifying anti-debug stubs; breaking here can lead you to the real code being revealed or patched in memory. |
| `GetProcAddress`                 | Shows when the binary dynamically resolves hidden anti-debug APIs (often from `ntdll`); the requested function name is a big giveaway. |
| `LoadLibraryExW`                 | Often paired with `GetProcAddress` to pull in `ntdll`/`user32` at runtime; breaking here can expose the moment advanced anti-debug tooling gets loaded. |

For those that are following along, here is an *x64dbg* command to add all these breakpoints:

```
bp kernel32.IsDebuggerPresent; bp kernel32.SetUnhandledExceptionFilter; bp kernel32.UnhandledExceptionFilter; bp kernel32.RaiseException; bp kernel32.QueryPerformanceCounter;  bp kernel32.GetTickCount;  bp kernel32.GetTickCount64;  bp kernel32.VirtualProtect;  bp kernel32.GetProcAddress;  bp kernel32.LoadLibraryExW
```

See [Anti-Debugging Breakpoints](###6.1 Anti-Debugging Breakpoints) for a more detailed breakpoint breakdown and logic tracing.



#### 5.2.2 Input Breakpoints

After, I decide to start with breakpoints that might be used for obtaining the user input from the console;

| Function            | Reason for Interest                                          |
| ------------------- | ------------------------------------------------------------ |
| `ReadConsoleA/W`    | Catches direct keyboard input from the console,can see exactly where the program reads the name/serial and what buffer it lands in. |
| `WriteConsoleA/W`   | Hits when the program prints prompts or messages; stepping right after often leads straight into the input and validation flow. |
| `ReadFile`          | Many console apps read STDIN via a handle as if it were a file, so this is a reliable fallback when `ReadConsoleA/W` isn’t used. |
| `WriteFile`         | Console output is sometimes routed through file-style writes, so it helps catch prompts and trace the execution path around user interaction. |
| `GetStdHandle`      | Usually called right before `ReadConsoleA/W`/`ReadFile` or output calls, so it’s a great “early warning” breakpoint for the I/O path. |
| `GetCommandLineA/W` | Useful when input is passed as command-line args; you can see raw input early before it gets parsed or transformed. Doesn't seem necessary for this CTF as it doesn't appear to use command line arguements, although it does not hurt to add it. |
| `GetProcAddress`    | Reveals dynamically resolved APIs (often hidden checks or CRT - C Runtime - calls); the requested function name can instantly expose the program’s real strategy. |

For those that are following along, here is an *x64dbg* command to add all these breakpoints:

```
bp kernel32.ReadConsoleW; bp kernel32.ReadConsoleA; bp kernel32.WriteConsoleW; bp kernel32.WriteConsoleA; bp kernel32.ReadFile; bp kernel32.WriteFile; bp kernel32.GetStdHandle; bp kernel32.GetCommandLineA; bp kernel32.GetCommandLineW; bp kernel32.GetProcAddress
```

See [Input Breakpoints](###6.2 Input Breakpoints) for a more detailed breakpoint breakdown and logic tracing.



------

## 6. Dynamic Analysis - Tracing Breakpoints and Stepping Over Logic

### 6.1 Anti-Debugging Breakpoints

With the breakpoints added, I resume program execution from the entry breakpoint.

![image-20251209025006530](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209025006530.png)



#### 6.1.1 The First Break - <kernel32.dll.LoadLibraryExW>

See [Windows x64 Calling Convention](###8.1 Windows x64 Calling Convention) for a quick refresher on Windows x64 calling convention.



Switching over to the *Call Stack* tab I can see that it is being directly called by the *PE*.

![image-20251209033617320](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209033617320.png)

`LoadLibraryExW` has three parameters and returns an *HMODULE* (or *NULL* on failure).

```c
HMODULE LoadLibraryExW(
  LPCWSTR lpLibFileName,
  HANDLE  hFile,
  DWORD   dwFlags
);
```

1. **lpLibFileName** (`LPCWSTR`)
   - Path or name of the DLL to load.
   - Often something like:
     - `L"kernel32.dll"`
     - `L"C:\\Windows\\System32\\something.dll"`
     - Or an app-local DLL name.
2. **hFile** (`HANDLE`)
   - Usually **NULL**.
   - Historically used for loading from an already-open file handle.
3. **dwFlags** (`DWORD`)
   - Controls *how* the module is loaded / searched.
   - Common ones include:
     - `0x00000000` → normal load
     - `LOAD_WITH_ALTERED_SEARCH_PATH`
     - `LOAD_LIBRARY_AS_DATAFILE`
     - `LOAD_LIBRARY_AS_IMAGE_RESOURCE`
     - `LOAD_LIBRARY_SEARCH_SYSTEM32`
     - `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`
     - `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`

If a weird flag value is present, it may be a *bitwise OR* of multiple flags.

- **Return Value**
  - Success: `HMODULE` for the loaded module.
  - Failure: **NULL** (`RAX = 0`).
    - Then `GetLastError()` can inform you as to why.



### 6.2 Input Breakpoints



------

## 7. Validation Path



---

## 8. Useful Notes and Reminders

### 8.1 Windows x64 Calling Convention

On Windows x64 calling convention:

- RCX = 1st parameter
- RDX = 2nd
- R8  = 3rd
- R9  = 4th
- RAX = return value
- If there are *more than four arguements*, the rest go on the *stack*.

#### 8.1.1 Volatile & Non-Volatile registers

Volatile (caller-saved): `RAX, RCX, RDX, R8–R11`

​		If you’re tracking values across calls, expect volatile regs to get clobbered.

Non-volatile (callee-saved): `RBX, RBP, RSI, RDI, R12–R15`

#### 8.1.2 Shadow Space

The caller reserves 32 bytes of *shadow space* on the stack before the call. So even if a function has fewer than 4 parameters, you’ll still see that stack layout pattern.

---

## 9.

---

## 10. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.
