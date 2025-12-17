# zsombii - Easy cracme — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/693d89b50992a052ab2222d7  
**Author:** *zsombii*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*, *Ghidra*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Multiplatform | 1.0 | 4.0 | java | Java |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\zsombii - Easy cracme\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]

---

## 1. Executive Summary

This document captures my reverse-engineering process for the crackme `crack the points` by `vilxd`. The target appears to be a Java binary.
- What the binary appears to be.
- Your overall approach.
- The key outcome so far.



---

## 2. Target Overview

### 2.1 UI / Behavior

- Inputs:
- Outputs:
- Expected protection level:

### 2.2 Screens

#### Start-up



#### Failure case





---

## 3. Tooling & Environment

- OS: *Windows 11*

- Debugger: *x64dbg*

- Decompiler: *Ghidra*

- Static tools: *CFF Explorer*, *Ghidra*

  

---

## 4. Static Recon

### 4.1 File & Headers

![][image4]

Notes:
- Architecture:
- Compiler hints:
- Packing/obfuscation signs:

### 4.2 Imports / Exports

![][image5]

Hypotheses:
- File I/O?
- Crypto?
- Anti-debug?



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

![][image6]

### 5.2 Entry Strategy

- Strings
- Breakpoints
- Message box hooks
- API logging



---

## 6. Validation Path



---

## 7. Patch Notes (If Allowed)



---

## 8. Findings Log



---

## 9. Conclusion

