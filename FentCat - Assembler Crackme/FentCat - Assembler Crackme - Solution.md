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

Double clicking on the string reference for "*Enter password* " brings me into the disassembly view where I start to poke and prod around. I land on what seems to be the `main` function. The methods `GetStdHandle` and `ReadConsoleA` from `KERNEL32.dll` are observable here.

![image-20251220153554255](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220153554255.png)

These calls seem to be responsible for outputting the string references onto the console.

![image-20251220153728279](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220153728279.png)

The `push` instructions are loading the string reference as a parameter for their following `call` instruction, which I presume is a `printf` call of sort.

The next few `push` instructions are preparing the parameters for the `ReadConsoleA` call.

![image-20251220190904090](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220190904090.png)

```c
BOOL ReadConsoleA(
    HANDLE  hConsoleInput,
    LPVOID  lpBuffer,
    DWORD   nNumberOfCharsToRead,
    LPDWORD lpNumberOfCharsRead,
    LPVOID  pInputControl
);
```

So, in the assembly code, the parameters can be labelled as the following.

```bash
push 0                          ; lpReserved
push crackme.734008             ; LPDWORD lpNumberOfCharsRead
push 100                        ; nNumberOfCharsToRead
push crackme.7320D9             ; lpBuffer
push dword ptr ds:[734000]      ; hConsoleInput
```

That means that the user input is being stored in `crackme.7320D9` and the length of the user input in `crackme.734008`.



------

## 6. Validation Path

Right after the call to `ReadConsoleA`, the input length is loaded into `EAX` and then compared against `0XA`. At first I thought this call was checking for empty input. After further analysis, I figured out it was actually comparing the user input length from `ReadConsoleA` against `0xA`.

![image-20251220191636639](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220191636639.png)

At first glance, it might seem that it is comparing the user input length against `0xA` (10) but it is important to keep in mind that in line mode, `ReadConsoleA` includes the `CR+LF` from you pressing Enter.

When you type in the console:

```
abc123⏎
```

what actually gets put into the buffer is (in hex):

```
61 62 63 31 32 33 0D 0A
 a  b  c  1  2  3  \r \n
```

So, the `cmp EAX, 0xA` instruction is checking if the user input is *8* characters long, not *10*. If the check fails, the logic jumps to `crackme.731099` which is the "*Authentication Failed*" logic.

![image-20251220192133329](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220192133329.png)

Following the `cmp EAX, 0xA` instruction is another `cmp` instruction, instead this time comparing `EAX` to `0x9` (9) - `cmp EAX, 0x9`.

![image-20251220192449322](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220192449322.png)

So these two `cmp` instructions are checking if the user input is *7* or *8* characters long, if it's not it jumps to the aforementioned "*Authentication Failed*" logic. If the length conditions are met, the logic jumps to further input validation which seems to be a call to `crackme.7310B8`.
Adding a breakpoint on that call and stepping into it reveals the following.

![image-20251220193002312](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251220193002312.png)

At the start of the function, it loads in the user input pointer into `ESI` and a global variable `crackme.7321DB` into `EDI`.

Loading `crackme.7321DB` in the *Dump* reveals the following.

```
007321DB  40 43 42 45 44 47 46 49 32 31 33 35 34 36 38 37  @CBEDGFI21354687  
007321EB  15 23 37 41 52 66 74 89 63 78 78 7A 78 63 76 00  .#7ARft.cxxzxcv.  
007321FB  66 66 61 67 64 73 6F 76 6A 32 33 65 00 52 46 47  ffagdsovj23e.RFG  
0073220B  58 47 61 4A 55 53 35 77 73 4A 6B 49 31 78 45 52  XGaJUS5wsJkI1xER  
0073221B  67 76 6A 6B 6B 61 31 68 6A 6E 6B 33 6B 00 74 46  gvjkka1hjnk3k.tF  
0073222B  73 44 49 4B 43 47 51 66 63 58 4A 79 68 62 53 31  sDIKCGQfcXJyhbS1  
0073223B  47 37 73 7A 47 65 6F 56 44 76 4F 43 52 4F 00 7A  G7szGeoVDvOCRO.z  
0073224B  64 66 67 68 6F 6F 6B 00 00 00 00 00 00 00 00 00  dfghook.........  

```



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