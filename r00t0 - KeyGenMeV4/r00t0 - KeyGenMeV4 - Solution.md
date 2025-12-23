# r00t0 - KeyGenMeV4 — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/690b3a032d267f28f69b7b56  
**Author:** r00t0  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*  

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 3.0 | 2.5 | x86-64 | C/C++    |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\r00t0 - KeyGenMeV4\cover.png" alt="cover" style="zoom:45%;" /></center>

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

- Inputs: **Accepts a name and a serial key to match the name.**
- Outputs: "*Nickname:* ", "*Serial key (hex):* ", 

### 2.2 Screens

#### Start-up

![image-20251222075212833](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075212833.png)

#### Failure case - Terminates on Invalid Serial

![image-20251222075903613](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075903613.png)

Note: for my start-up screenshot, it just terminated without any output.



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*
- Decompiler: *Ghidra*
- Static tools: *CFF Explorer*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251222074758880](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074758880.png)

Notes:
- Architecture:
- Compiler hints:
- Packing/obfuscation signs:



### 4.2 Imports / Exports

![image-20251222074813538](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074813538.png)

Hypotheses:
- File I/O?
- Crypto?
- Anti-debug?



#### 4.2.1 KERNEL32.dll

![image-20251222074845476](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074845476.png)

![image-20251222074857608](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074857608.png)

![image-20251222074907969](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074907969.png)



#### 4.2.2 msvcrt.dll

![image-20251222074950118](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222074950118.png)

![image-20251222075001303](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075001303.png)

![image-20251222075012685](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075012685.png)



#### 4.2.3 ntdll.dll

![image-20251222075046818](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075046818.png)



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x64dbg* yields no immediate or obvious signs of any anti-debugging logic.

### 5.2 String Driven-Entry

Searching for string references within the target *Portable Executable* (*PE*) yields a ton of results, to save time I have added a "*Serial*" and "Nickname" keyword to filter the string references.

![image-20251222075750367](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222075750367.png)

![image-20251222080053681](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222080053681.png)

I decide to start with the *Nickname* input. Double clicking on the string reference for "*Nickname:* " brings me into the disassembly view where there seems to be nothing of interest. So I proceed to the first reference of "*Wrong serial key*". Going down the list, each reference brings me somewhere I don't care to be.



### 5.3 Breakpoints

Time to add some breakpoints. Going through [msvcrt.dll](####4.2.2 msvcrt.dll), I pinpoint any method of interest and add a breakpoint on it;
`puts, printf, fwrite, fputs, fputc, fgets`. I disable all breakpoints except `fgets` as this is most likely how the input is being retrieved from the console.



#### 5.3.1 fgets

It breaks as expected when attempting to retrieve the `Nickname`. I continue out of the return and land somewhere I can't exactly make out what it's doing just yet.

![image-20251222095231572](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222095231572.png)

It’s a **hook/wrapper** around `fgets`, what is referred to as “*CRT glue*”. **CRT glue code** is the little bits of code the **C RunTime (*CRT*)** adds around your program, *not* written by the crackme author.

Key lines:

```
D000DB | FF35 97 00 00 00 | push qword ptr ds:[D00178]
...
D00105 | 48:8B8C24 88000000 | mov rcx,qword ptr ss:[rsp+88] ; <- loads original return address
...
D0016B | 4C:8B3D 76000000   | mov r15,qword ptr ds:[D001E8]
D00172 | 48:83C4 08         | add rsp,8
D00176 | FFE1               | jmp rcx                      ; <- jump back to caller
```

What it’s doing:

1. **Save everything**: flags, rax/rbx/…/r15, some pointers, etc.
2. Call the real `fgets` (that happened before this block).
3. **On return**, restore everything from those `D001xx` globals.
4. Load the original caller’s return address into `RCX` (`mov rcx,[rsp+88]`).
5. `jmp rcx` – transfer control straight to the instruction *after* the original `call fgets`.

So this is just a trampoline. You’re one hop away from the actual code you care about. Proceeding to the `jmp rcx` lands us somewhere that is now starting to look more like a regular `main` function - or at least I hope.

![image-20251222095111782](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222095111782.png)

It seems that once the user input is returned from the `fgets` wrapper it is moved into `ss:[RBP+5C0]` from `RAX`. `ss:[RBP+5C0]` is a local address, so when trying to find references to addresses, a lot appeared.

![image-20251222103259622](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222103259622.png)

I instead pivot to adding a hardware breakpoint on the address of `[RBP+5C0]` which is `0000000000FCFD48`. I notice some interesting behaviour where it is using an offset of `+88` off the address, but again, it becomes difficult to trace. I am also starting to suspect that this *PE* might be obfuscated.

This is where I switch to *Ghidra* alongside *x64dbg*.



---

## 6. Ghidra

I start by looking at the `entry` function.

![image-20251222114701529](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222114701529.png)

After stepping through both the calls, it seems that the second one is a call to a trampoline that calls some actual code function logic.

![image-20251222114755235](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222114755235.png)

Which lands us on this function.

![image-20251222114804750](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251222114804750.png)

Which is a call to `VirtualAlloc`, I assume that it is using this to load in the actual validation logic perhaps.



---

## 7. Utilizing Ghidra + x64dbg


After the `VirtualAlloc` call I set a breakpoint on the address in `RAX` which is the memory spaced that was allocated by `VirtualAlloc`. The breakpoint is never hit and it seems that whilst watching the *Dump* view of that memory region provided by `VirtualAlloc`, it never gets overwritten and stays `0x00` across the board.

![image-20251223110236586](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223110236586.png)

After the call to `VirualAlloc` - `call rax` - there is a `jmp` instruction. Following that jump leads me to the following code which looks like a function.

![image-20251223110334539](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223110334539.png)

I notice at the start there is a huge stack frame being allocated `0x1608` and a bunch of registers being saved onto the stack so they can be used, which is consistent with a *function prologue*.

Those `push` instructions are saving *callee-saved* registers. On *Windows x64*, some registers are *callee-saved*, meaning if a function wants to use them it must **restore them before returning**: `RBX, RBP, RSI, RDI, R12, R13, R14, R15`. The top stub is pushing all of them.

```assembly
push rbp
push r15
push r14
push r13
push r12
push rsi
push rdi
push rbx
```

After stepping through and further analysing the function I determine that it is of no importance to my goal. Once again, I have been chasing nothing, which is starting to become a re-accuring theme in this *crackme*.



I decide to go back to the `entry` function in *Ghidra* to help locate it within *x64dbg*. Thankfully, *x64dbg* already has an option to break on this `entry` function in the *Options* - *Preferences* menu.

![image-20251223113211875](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223113211875.png)

We can see that we are in the same place in *Ghidra* and *x64dbg*.

![image-20251223113308660](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223113308660.png)



![image-20251223113253599](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223113253599.png)

From my earlier findings, I know that the second `call` instruction is the one that actually runs the *crackme* logic, the `main` function. I add a breakpoint on it and step into it. Time to start analysing and going through this huge chunk of change.

![image-20251223113434673](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223113434673.png)





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