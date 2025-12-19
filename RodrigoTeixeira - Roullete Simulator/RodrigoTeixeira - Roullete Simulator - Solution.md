# RodrigoTeixeira - Roullete Simulator — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/693c48822d267f28f69b8518  
**Author:** *RodrigoTeixeira*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer, x64dbg*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 3.0 | 4.0 | java | Java |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\RodrigoTeixeira - Roullete Simulator\cover.png" alt="cover" style="zoom:45%;" /></center>

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

- Inputs:
- Outputs:
- Expected protection level:

### 2.2 Screens

#### Start-up

![][image1]

#### Failure case

![][image2]



---

## 3. Tooling & Environment

- Static tools:
- OS: *Windows 11*
- Debugger: *x64dbg*
- Decompiler:
- Static tools: *CFF Explorer*



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



---

## Appendix A —  Reference Notes

- Addresses:
- Breakpoints list:
- Useful commands: