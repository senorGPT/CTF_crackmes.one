# FentCat - Assembler Crackme — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/68fce1922d267f28f69b783a  
**Author:** *FentCat*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x32dbg*  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.0 | 3.5 | x86 | Assembler |

---

<center><img src="C:\Users\david\Desktop\crackmes.one\FentCat - Assembler Crackme\cover.png" alt="cover" style="zoom:45%;" />

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy  

---

[TOC]

---

## 1. Executive Summary

Briefly describe:
- What the binary appears to be.
- Your overall approach.
- The key outcome so far.



---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs: **Accepts user input for a password.**
- Outputs: "*AdvancedCrackMe v2.0*",  "*Hint: The password transforms mysteriously*", "*Warning: System integrity check running...*", "*Enter password*", "*Authentication Failed*"
- Expected protection level: Assume that there is some kind of anti-debugging due to the "*Warning: System integrity check running...*" message.

### 2.2 Screens

#### Start-up

![image-20251220044142587](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220044142587.png)

#### Failure case

![image-20251220044127476](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220044127476.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x32dbg*
- Decompiler (if applicable):
- Static tools: *CFF Explorer*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251220044621366](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220044621366.png)

Notes:
- Architecture:
- Compiler hints:
- Packing/obfuscation signs:

### 4.2 Imports / Exports

![image-20251220044636955](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220044636955.png)

Hypotheses:
- File I/O?
- Crypto?
- Anti-debug?



#### 4.2.1 KERNEL32.dll

![image-20251220044702068](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220044702068.png)

Nothing stands out as any immediate anti-debugging calls.



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x32dbg* yields no immediate or obvious signs of any anti-debugging logic.



### 5.2 String Driven-Entry

Searching for string references within the target *Portable Executable* (*PE*) yields results the following results.

![image-20251220045227480](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220045227480.png)



---

## 6. Validation Path



---

## 7. Patch Notes (If Allowed)



---

## 8. Findings Log



---

## 9. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.



---

## Appendix A —  Reference Notes

- Addresses:
- Breakpoints list:
- Useful commands: