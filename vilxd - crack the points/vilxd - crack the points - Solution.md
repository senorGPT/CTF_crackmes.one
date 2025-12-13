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

I trace the logic out of the function and land within what appears to just be the `main` function?

![image-20251213031207130](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213031207130.png)

Restarting program execution and going back into that first function I notice that after the second `call` instruction the string is output to console. I proceed to step into that function.

![image-20251213030159338](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251213030159338.png)





---

## 6. Validation Path



---

## 7. Patch Notes (If Allowed)

Describe:
- What you changed (high level).
- Why it works.
- How you verified behavior.



---

## 8. Findings Log



---

## 9. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.

