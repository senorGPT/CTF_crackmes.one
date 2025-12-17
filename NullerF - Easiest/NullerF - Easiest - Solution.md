<!--
Reverse Engineering Write-up Template (Typora-friendly)
Copy this file and replace placeholders.
-->

# <challenge name> — Reverse Engineering Write-up

**Challenge link:** <url>  
**Author:** <author>  
**Write-up by:** <your name/handle>  
**Tools used:** <tools>  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| <platform> | <difficulty> | <quality> | <arch> | <language> |

---

## Cover Snapshot

> **Status:** <WIP / Complete>  
> **Goal:** <one-sentence objective>  

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

### 6.1 Input Acquisition

Where the program reads:
- Name:
- Key:

### 6.2 Parsing / Normalization

Document any:
- string → integer conversions
- base/encoding expectations

### 6.3 Transformation

List steps in order with pseudocode.

```c
// pseudocode here
```

### 6.4 Compare / Branch

Show the critical conditional(s).

---

## 7. Patch Notes (If Allowed)

Describe:
- What you changed (high level).
- Why it works.
- How you verified behavior.

---

## 8. Findings Log

| Step | What I did | What I learned |
|---|---|---|
| 1 |  |  |
| 2 |  |  |

---

## 9. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.

---

## Appendix A — Screenshot Map

```
./assets/
  image1.png
  image2.png
  image3.png
  image4.png
  image5.png
  image6.png
```

---

## Appendix B — Reference Notes

- Addresses:
- Breakpoints list:
- Useful commands: