# NemesisX - GuessPassword — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/6934194d2d267f28f69b8379  
**Author:** *NemesisX*  
**Write-up by:** *SenorGPT*  
**Tools used:** *x64dbg*  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 3.5 | 2.5 | x86-64 | Unspecified/other - Python |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\NemesisX - GuessPassword\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** WIP  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy   

---

[TOC]

---

## 1. Executive Summary

This document captures my reverse-engineering process for the crackme `GuessPassword` by `NemesisX`. The target appears to be a simple command line process that prompts the user for a password.

I successfully:

- Performed basic static reconnaissance.
- Surveyed imports. Confirmed there appears to be anti-debugging measures.
- Tried to locate strings associated with success & failure dialogs.
- Added breakpoints on functions that may be used for anti-debugging and begun to trace logic.
- Discovered the input validation and reverse engineered the encoding and comparison logic.

​	

---

## 2. Target Overview

### 2.1 UI / Behavior

- Inputs:
- Outputs:
- Expected protection level:

### 2.2 Screens

#### Start-up

![][image1]

#### Failure case

![][image2]

#### Success case (if known)

![][image3]



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*

- Static tools: *CFF Explorer, Detect It Easy (DIE)*



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

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.
