# <Biglsim04 puzzle>

# Biglsim04's puzzle — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/691de1d12d267f28f69b7f16  
**Author:** Biglsim04  
**Write-up by:** SenorGPT  
**Tools used:** CFF Explorer, x64dbg  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.5 | 3.5 | x86-64 | C/C++ |

---

## Cover Snapshot

> **Status:** WIP  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]

---

## 1. Executive Summary

This document captures my reverse-engineering process for `puzzle` crackme by `Biglsim04`. The target appears to be a simple command line process that prompts the user for a password.
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

![image-20251207212319705](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251207212319705.png)

#### Failure case

![][image2]

---

## 3. Tooling & Environment

- OS:
- Debugger:
- Decompiler (if applicable):
- Static tools:

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

Describe:
- What you changed (high level).
- Why it works.
- How you verified behavior.

---

## 8.

---

## 9. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.
