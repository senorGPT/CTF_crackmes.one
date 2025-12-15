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
- Surveyed imports. Confirmed there appears to be anti-debugging measures.
- Tried to locate strings associated with success & failure dialogs.
- Added breakpoints on functions that may be used for anti-debugging and begun to trace logic.
- Discovered the input validation and reverse engineered the encoding and comparison logic.



---

## 2. Target Overview

### 2.1 UI / Behavior

- Inputs:
- Outputs: *Your count points is 0*

### 2.2 Screens

#### Start-up

![image-20251213023218995](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213023218995.png)

#### Failure case

![image-20251213023251447](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213023251447.png)



---

## 3. Tooling & Environment

- OS:
- Debugger:
- Decompiler (if applicable):
- Static tools:



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
- Library or runtime internals (*scanf/strtol*, *CRT* startup, etc.)



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

This makes it clear that `DAT_140013018` represents the `points`. Let's go ahead and rename it. *Right clicking `DAT_140013018`* - *Edit Label*; I change it to `POINTS`. Now with a more human readable name, it should be a easier to spot and trace when looking at the assembly / pseudo code. *Right clicking `POINTS`* - *References* - *Show References* to Points (shortcut: *CTRL + SHIFT + F*); Opens a window with all references to the `POINTS` variable.

![image-20251215010845947](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251215010845947.png)

The second reference `LEA _Argc, [POINTS]` is the instruction from the `main` function we just came from so I ignore it. Clicking on the first reference brings us into another function, which again we aren't seeing for the first time.





---

## 7. Validation Path



---

## 8. Patch Notes (If Allowed)

Describe:
- What you changed (high level).
- Why it works.
- How you verified behavior.



---

## 9. Findings Log



---

## 10. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.

