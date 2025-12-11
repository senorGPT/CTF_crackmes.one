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

- Tried to locate strings associated with success & failure dialogs.

- Added breakpoints on functions that may be used for anti-debugging and begun to trace logic.

  

---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs: *Enter password:*
- Outputs: *Access Denied*, *Access Accepted* (assumption based on wrong answer string).

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

There appears to be no obvious signs of packing or obfuscation. The classic boring set of sections `.text`, `.rdata`, `.data`, `.reloc` represent a very typical layout for an unprotected Visual Studio type Portable Executable (*PE*).
The sizes also seem reasonable for a small console application.

![image-20251208085118755](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085118755.png)

Packed binaries often show one or more of these red flags:

- **Weird section names:**
  `.UPX0, .UPX1, .aspack, .petite`, or just random gibberish.

- **Very few sections:**
  Sometimes just one or two suspicious ones.

- **Abnormal size balance:**
  A tiny `.text` with a huge other section holding compressed payload.

It is *IMPORTANT* to note that headers alone can not confirm if the *PE* has been packed or obfuscated as the packer/obfuscator used might utilize normal looking section names, keep a standard layout, and/or hide the real tell in entropy or runtime behaviour.



### 4.2 Entropy

Entropy is a measure of how *random-looking* the bytes are in a section.

- Low entropy = looks like normal code/data (more patterns, more repetition).
- High entropy = looks compressed or encrypted (more random).

Why this matters:

- Packed or encrypted payloads often have high entropy.
- Normal `.text` code usually has moderate entropy.

Rule of thumb (quick reference, not 100%):

- ~6.0–7.2 = often normalish

- ~7.4–8.0 = suspicious for compression/encryption

  

Unfortunately, *CFF Explorer* does not have an entropy viewer so I switch to *DIE*.

![image-20251209031847854](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209031847854.png)

The top blue bar shows *DIE*'s overall heuristic guess based mostly on entropy patterns and layout. This is not necessarily proof, but a strong hint that this is not classically packed.

The table shows each row as a region - header + each *PE* section - with an entropy score.

| Section Name | Entropy Score | Note                                                         |
| ------------ | ------------- | ------------------------------------------------------------ |
| *PE* Header  | 2.51659       | Low entropy is normal for headers.                           |
| .text        | 6.44770       | normal looking code entropy. If this was packed or encrypted the value would be closer to ~7.5–8.0. |
| .rdata       | 4.66111       | Normal for constants/strings/tables.                         |
| .data        | 2.64577       | Very normal (initialized globals).                           |
| .reloc       | 5.29263       | Also not unusual.                                            |

Nothing here also seems to scream that this *PE* is packed.

Finally, the graph represents a rolling entropy line across the file from start to end. The long flatish area around *~6* matches the `.text` region.
The later dips and spikes reflect transitions into `.rdata`, `.data`, `.reloc`.

Again, if this *PE* was packed the graph would have a big chunk of the line hovering around *~7.4-8*.



### 4.3 Build & Toolchain Information

Screenshot summary provided by *DIE*

![image-20251209030922816](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209030922816.png)

**Operation system: Windows(Vista)AMD64, 64-bit, Console**
The binary is a *64-bit Windows console app*. The *Vista* part usually reflects the *minimum subsystem version* or tool heuristics and *NOT* that it only runs on Vista.

**Linker: Microsoft Linker (14.36.34123)**
The exact *MSVC linker version* used to produce the EXE.

**Compiler: Microsoft Visual C/C++ (19.36.34123) [LTCG/C]**
Identifies the *Visual C++ compiler version*.
**LTCG** = *Link-Time Code Generation* (whole-program optimization). The `/C` part is just the tool’s way of labelling the language/compile family.

**Language: C**
*DIE*’s best guess for source language. In practice, this likely means *C or C++* with a C-like signature.

**Tool: Visual Studio(2022, v17.6)**
Maps those version numbers to the likely *IDE/toolchain family* that was used to build the *EXE*.



### 4.4 Imports / Exports

Since it is a simple console application, the only import *SEEMS* to be `KERNEL32.dll`.

|<img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085207040.png" alt="image-20251208085207040" style="zoom: 50%;" /> | <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085248818.png" alt="image-20251208085248818" style="zoom: 50%;" /> | <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251208085310279.png" alt="image-20251208085310279" style="zoom: 50%;" />



#### 4.4.1 KERNEL32.dll

Off the bat I notice at least one *VERY* interesting function that is commonly used as a direct check for anti-debugging, `IsDebuggerPresent`.

Other functions that caught my eye are the timing functions; `QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64`, `GetSystemTimeAsFileTime`. These aren't necessarily indicative of anything, but *could* be used to support debugger detection logic by performing timing checks.

`GetCurrentProcessId`, `GetStartupInfoW`, and `GetCurrentThreadId` *could* also be used as anti-debug logic to check for certain flags or conditions on the program itself.

`LoadLibraryExW`, `GetProcAddress` and `FreeLibrary` *could* be used to hide libraries/modules by dynamic resolution.

`GetLastError`, `SetLastError`, `RaiseException`, `UnhandledExceptionFilter`, and `SetUnhandledExceptionFilter` *could* all be used in exception based anti-debugging measures.

`IsProcessorFeaturePresent` is also interesting as it *could* be used for certain anti-debug exception tricks.

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

Nada! Well that's a first for me, never before have I had it where there are zero string references found. Something new is always interesting!

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

See [Windows x64 Calling Convention](###8.1 Windows x64 Calling Convention) for a quick refresher on Windows x64 calling convention.



### 6.1 Anti-Debugging Breakpoints

With the new breakpoints added, I resume program execution from the entry breakpoint.

![image-20251209153246036](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209153246036.png)

I disabled the `GetTickCount` breakpoint as it was getting triggered on each frame, instead replacing it with a breakpoint in the caller that I hope will bring me closer to the flag comparison logic.

There seems to be more going on than a simple console checker. `GetProcAddress` (x17) + `LoadLibraryExW` (x9) on start-up shows that the binary is *OR* might-be keeping the static import table small/boring and resolving lots of APIs at runtime.

I also noticed that `IsDebuggerPresent` breakpoint never gets triggered, even upon input validation.



#### 6.1.1 kernel32.dll.LoadLibraryExW

See [LoadLibraryExW Function Definition](####8.2.1 kernel32.dll.LoadLibraryExW) for function definition details.



Switching over to the *Call Stack* tab I can see that it is being directly called by the *PE*. This means that the target binary is the one actually making the call to `LoadLibraryExW` and not some other module/code.

![image-20251209033617320](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209033617320.png)

Continuing the execution into `KERNEL32.DLL.LoadLibraryExW` I see that the following registers have the values:

- **Call #1** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B937E0 | L"api-ms-win-core-synch-l1-2-0"             |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #2** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B937A0 | L"api-ms-win-core-fibers-l1-1-1"            |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #3** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B95E90 | L"api-ms-win-core-fibers-l1-1-2"            |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #4** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B95F80 | L"api-ms-win-core-localization-l1-2-1"      |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #5** - Likely normal runtime/loader behaviour.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B93820 | L"kernel32"                                 |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #6** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B96080 | L"api-ms-win-core-string-l1-1-0"            |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #7** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                        |
| -------- | ---------------- | ------------------------------------------- |
| RCX      | 00007FF685B95E50 | L"api-ms-win-core-datetime-l1-1-1"          |
| RDX      | 0000000000000000 |                                             |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800 |

- **Call #8** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                            |
| -------- | ---------------- | ----------------------------------------------- |
| RCX      | 00007FF685B95FD0 | L"api-ms-win-core-localization-obsolete-l1-2-0" |
| RDX      | 0000000000000000 |                                                 |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800     |

- **Call #9** - Most likely *normal OS dependency resolution* with a *safe flag* restricting search to *System32*.

| Register | Value            | Note                                          |
| -------- | ---------------- | --------------------------------------------- |
| RCX      | 00007FF685B961D0 | L"api-ms-win-security-systemfunctions-l1-1-0" |
| RDX      | 0000000000000000 |                                               |
| R8       | 0000000000000800 | `LOAD_LIBRARY_SEARCH_SYSTEM32` = 0x00000800   |



The binary consistently restricts DLL search to System32 during early initialization which aligns with modern safe-loading practices and reduces the likelihood of DLL search-order hijacking. The `api-ms-win-*` entries reflect Windows API-set indirection. Their presence here is typical for modern MSVC builds and does not by itself indicate obfuscation. None of the observed `LoadLibraryExW` function calls directly load `ntdll.dll` or other modules - `user32.dll`, `dbghelp.dll` - commonly associated with advanced anti-debug checks. The initial loads appear consistent with baseline OS/runtime dependencies.



#### 6.1.2 kernel32.dll.SetUnhandledExceptionFilter

See [SetUnhandledExceptionFilter Function Definition](####8.2.2 kernel32.dll.SetUnhandledExceptionFilter) for function definition details.



Return value is `NULL` (00000000), indicating no prior top-level exception filter was registered before this call. Nothing interesting happening here, so I continue on to the next breakpoint.



#### 6.1.3 kernerl32.dll.GetTickCount64

See [GetTickCount64 Function Definition](####8.2.3 kernerl32.dll.GetTickCount64) for function definition details.



Since `GetTickCount64` is only called once I decide to investigate what it's being used for. Upon hitting the breakpoint, I hit Debug - Execute till return (CTRL + F9) and get to the caller. Alternatively, using the *Call Stack* would bring me to the same location by clicking on the frame underneath the `GetTickCount64` frame.

My first guess without diving too deep into this function is that it might be generating some kind of value from the system time. This value could then be used as an encoding seed of sorts (***just a guess***).

![image-20251209184706474](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251209184706474.png)

An interesting instruction I notice is `rdtsc` which reads the CPU's *Time Stamp Counter* (*TSC*). The return is a *64-bit number* that usually increases constantly whilst the system runs. After the instruction, `EAX` holds the *low 32-bits* and `EDX` holds the *high 32-bits*. These are then usually combined by an `or` instruction.

![image-20251210014935078](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251210014935078.png)

It also appears to be doing some kind of encoding and transformation based off the return values from `rdtsc` and `GetTickCount64`.

After spending some time decoding each instruction it does indeed seem like it creates some kind of seed value and stores it within a global.

![image-20251211005825753](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211005825753.png)

Seems like progress. I added a breakpoint of the instruction `mov byte ptr ds:[7FF865BA3264], al` to keep track of the seed on subsequent executions and proceeded to the return, which lands me in another function.

![image-20251211014415363](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211014415363.png)

This function appears to loop until `RBX == RDI`, at which point it calls the seeding function that uses `GetTickCount64`. What exactly `RDI` is I am unaware of yet.



#### 6.1.4 Switching my approach

I'm starting to think that a lot of functions might have been imported and never used *OR* just imported as red-herrings. This has caused me to search in unnecessary areas instead of trying to track down any anti-debugging logic. I will switch gears to attempt to find the flag and see if I trip up any anti-debug code along the way. 



### 6.2 Input Breakpoints

Two of the breakpoints that end up producing interesting results are `WriteFile` and `ReadFile`. There seems to be some kind of loop that iteratively prints `Hello World!\nEnter password: `. This would explain why I was unable to find any string references ix *x64dbg*, as it seems to be dynamically loading and printing the value. This doesn't seem an avenue worth exploring as it just handles the output to console.
Taking note of this, I continue to where the user input is captured as I feel that would achieve more desirable results.



#### 6.2.1 kernel32.dll.WriteFile

After stepping around I land on an interesting function.

![image-20251211023312358](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211023312358.png)

The first immediate thing that stands out to me is the repeated loops to an index of `0x40`.

The two loops at the start take some time but eventually click for me. The first loop I found in the long function just takes the user input up until a newline character and then checks if it is 9 characters long.

![image-20251211043226186](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211043226186.png)

Continuing the execution, I get to the loop that prints "*Access Denied*" onto the screen.

![image-20251211035110391](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211035110391.png)

Above it, I notice a similar looking loop. Considering the conditional before it, I assume that it is the "*Access Allowed*" branch.

![image-20251211035158630](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211035158630.png)

Great, so I - *think I* - have found where the comparison takes place before the right/wrong branches. My next step revolves around setting a breakpoint on that `test dl, dl` and restarting program execution to see what the registers look like. 

![image-20251211040357082](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211040357082.png)

One thing that I am really starting to notice is the repeated use of the value `0x40`, especially for loops. Breaking there, it seems that the important code is not around there but a bit higher. 

A bit above there seems to be a loop that checks if the user input is 9 characters long. If it's not, it jumps to the *"Access Denied"* code branch.

![image-20251211042357251](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211042357251.png)

Changing my input from `helloworld` to `helloworl` I confirm that it indeed is checking the length of the user input and ensuring it is 9 characters long. With that, I continue into the logic that was being jumped over.

![image-20251211042630372](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211042630372.png)

And I think I spot the smoking gun.



------

## 7. Validation Path

The actual flag comparison logic!
`RAX` (`AL`) represents a character from our user input being compared against `RCX` (`CL`) which I assume is the respective index character of the flag.

![image-20251211043318468](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211043318468.png)

Now to just extract the flag character. BUT, before doing so I temporarily `nop` the `jne` instruction as to not jump to the "*Access Denied*" branch. 

![image-20251211043806038](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211043806038.png)

As I run the program from my breakpoint on the `cmp cl, al` instruction; the `RAX` register spell out: `M`, `Y`, `P`, `A`, `S`, `S`, `1`, `2`, `3`.

Time to enter the password `MYPASS123` and see if it is indeed the correct flag.

![image-20251211044338447](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211044338447.png)

***Great success!***



---

## 8. Useful Notes, Reminders, and Definitions

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

The caller *MUST* reserve 32 bytes of *shadow space* on the stack before the call. So even if a function has fewer than 4 parameters, you’ll still see that stack layout pattern. It’s there so the *callee* has a guaranteed place to spill the first four register arguments if it wants: `RCX`, `RDX`, `R8`, `R9`.



#### 8.1.3 Stack Alignment

*Windows x64* requires the stack to be *16-byte aligned at the moment of a `call`*. This is because the `call` instruction pushes an *8-byte* return address, which shifts `RSP` by 8 and can break *16-byte* alignment.



### 8.2 Function Definitions

#### 8.2.1 kernel32.dll.LoadLibraryExW

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

| Flag                                  | Value        | Note                                                         |
| ------------------------------------- | ------------ | ------------------------------------------------------------ |
|                                       | `0x00000000` | Default load behaviour (normal DLL search order).            |
| `DONT_RESOLVE_DLL_REFERENCES`         | `0x00000001` | Maps the DLL but *doesn’t call* `DllMain` or resolve imports - useful for inspection. |
| `LOAD_LIBRARY_AS_DATAFILE`            | `0x00000002` | Loads the module *as a data file* (resources), not for code execution. |
| `LOAD_LIBRARY_AS_IMAGE_RESOURCE`      | `0x00000020` | Loads *only as an image resource*, mostly for resource access. |
| `LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE`  | `0x00000040` | Like `AS_DATAFILE` but tries to keep it exclusive so others can’t modify it. |
| `LOAD_WITH_ALTERED_SEARCH_PATH`       | `0x00000008` | Changes search order to prioritize the DLL’s directory - older/legacy pattern. |
| `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`    | `0x00000100` | Search the directory of the DLL being loaded                 |
| `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` | `0x00000200` | Search the executable’s directory                            |
| `LOAD_LIBRARY_SEARCH_USER_DIRS`       | `0x00000400` | Search directories added via `AddDllDirectory`               |
| `LOAD_LIBRARY_SEARCH_SYSTEM32`        | `0x00000800` | Search `System32` only                                       |
| `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`    | `0x00001000` | A safe default set: app directory + system32 + user-added directories (recommended modern choice). |

If a weird flag value is present, it may be a *bitwise OR* of multiple flags.

- **Return Value**
  - Success: `HMODULE` for the loaded module.
  - Failure: **NULL** (`RAX = 0`).
    - Then `GetLastError()` can inform you as to why.

[Jump Back](####6.1.1 kernel32.dll.LoadLibraryExW)



#### 8.2.2 kernel32.dll.SetUnhandledExceptionFilter

`SetUnhandledExceptionFilter` accepts one parameter and returns an *LPTOP_LEVEL_EXCEPTION_FILTER* which is the previous unhandled exception filter (or *NULL* if none).

```c
LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
);
```

1. **lpTopLevelExceptionFilter** (`LPTOP_LEVEL_EXCEPTION_FILTER`)
   - Pointer to a *custom unhandled exception filter* function.
   - This function is called when an exception *isn't handled* by structured exception handling in the process.
   - Often something like:
     - `MyUnhandledExceptionFilter`
     - `NULL` (to clear/disable a previously set filter)

- **Return Value** (`LPTOP_LEVEL_EXCEPTION_FILTER`)
  - Returns a pointer to the *previous* unhandled exception filter.
  - Often:
    - Another filter function pointer if one was already set
    - `NULL` if no previous filter was registered

[Jump Back](####6.1.2 kernel32.dll.SetUnhandledExceptionFilter)



#### 8.2.3 kernerl32.dll.GetTickCount64

`GetTickCount64` takes no parameters and returns a *ULONGLONG* representing the number of milliseconds that have elapsed since the system was started.

```c
ULONGLONG GetTickCount64(
    VOID
);
```

- **Return Value (`ULONGLONG`)**
  - Returns the number of **milliseconds since system boot**.
  - Often used for:
    - timing measurements
    - detecting delays (e.g., anti-debug “single-step slowdown” checks)

[Jump Back](####6.1.3 kernerl32.dll.GetTickCount64)



### 8.3 x64 Register Size Cheat Sheet

Each 64-bit register has smaller *views*; Example with `RAX`:

| Size         | Name  | What it is                     |
| ------------ | ----- | ------------------------------ |
| 64-bit       | `RAX` | full register                  |
| 32-bit       | `EAX` | low 32 bits of `RAX`           |
| 16-bit       | `AX`  | low 16 bits                    |
| 8-bit (low)  | `AL`  | low 8 bits                     |
| 8-bit (high) | `AH`  | bits 8–15 (upper half of `AX`) |

*So* `AX = AH:AL`. The same pattern applies to others



**Common Registers;** High *8-bit* forms exist only for these classic registers:

| 64-bit  | 32-bit | 16-bit | 8-bit low | 8-bit high* |
| ------- | ------ | ------ | --------- | ----------- |
| **RAX** | EAX    | AX     | AL        | AH          |
| **RBX** | EBX    | BX     | BL        | BH          |
| **RCX** | ECX    | CX     | CL        | CH          |
| **RDX** | EDX    | DX     | DL        | DH          |

**Pointer/Index Registers;** These do *NOT* have `AH/BH/CH/DH` style high *8-bit* forms.

| 64-bit  | 32-bit | 16-bit | 8-bit low |
| ------- | ------ | ------ | --------- |
| **RSI** | ESI    | SI     | SIL       |
| **RDI** | EDI    | DI     | DIL       |
| **RBP** | EBP    | BP     | BPL       |
| **RSP** | ESP    | SP     | SPL       |

**Extended registers (x64-only);** No high *8-bit* halves here either:

| 64-bit  | 32-bit | 16-bit | 8-bit low |
| ------- | ------ | ------ | --------- |
| **R8**  | R8D    | R8W    | R8B       |
| **R9**  | R9D    | R9W    | R9B       |
| **R10** | R10D   | R10W   | R10B      |
| **R11** | R11D   | R11W   | R11B      |
| **R12** | R12D   | R12W   | R12B      |
| **R13** | R13D   | R13W   | R13B      |
| **R14** | R14D   | R14W   | R14B      |
| **R15** | R15D   | R15W   | R15B      |

Important to note that writing to a *32-bit* register, such as `EAX`, *zeroes* the upper 32 bits of the 64-bit register (`RAX`).



---

## 9. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.



- Spent too much time on anti debugging code when none was really present
- Wasted a lot of time investigating code that had nothing to do with my end goal of finding the flag
