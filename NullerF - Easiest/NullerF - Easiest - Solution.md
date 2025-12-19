# NullerF - Easiest — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/6906250b2d267f28f69b7a50  
**Author:** *NullerF*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer, x64dbg*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 1.1 | 3.8 | x86-64 | C/C++ |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\NullerF - Easiest\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy 

---

[TOC]

---

## 1. Executive Summary

This write-up documents my reverse-engineering process for `Easiest.exe` by `NullerF`, a *Windows x86-64 C/C++* crackme that prompts the user for a numeric PIN and prints either a success or failure message.

I started with light static recon in *CFF Explorer* to get a feel for the layout. One oddity is the number of extra sections named like `/4`, `/19`, `/31`, etc. These are *Common Object File Format* (*COFF*) string table references. The section name field is only 8 bytes, so longer names get stored in the *COFF* string table and referenced via `/<decimal_offset>`.
Despite the strange section layout, the imports didn’t immediately scream “protector/anti-debug” and a baseline debug run in *x64dbg* looked clean.

From there, I used a string-driven approach: I located the `"Enter PIN:"` string and followed its reference, which dropped me directly into `main`.



---

## 2. Target Overview

### 2.1 UI / Behavior

- Inputs: **Prompts user to input a PIN**
- Outputs: "*Incrorrect :/*"

### 2.2 Screens

#### Start-up

![image-20251218235721751](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218235721751.png)

#### Failure case

![image-20251218235830825](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218235830825.png)





---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*
- Static tools: *CFF Explorer*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251218234754221](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218234754221.png)

The **weird part** is the **large number of extra sections** named like `/4`, `/19`, `/31`, etc., each:

- **page-aligned** (Virtual Address jumps by 0x1000)
- with **Raw Size = 0x200** (minimal file alignment chunk)
- and **tiny Virtual Size**

That pattern is *not* normal for a simple compiler/linker output. It often can suggest one of following; **packer/protector** splitting data across many sections, **manual section munging** (anti-analysis / parser confusion), **long/merged section naming weirdness** (see next section), sometimes combined with stripping symbol/string data.

The section names that start with `/` are *COFF* “string table” references. *Portable Executable* (*PE*) section names are stored in an 8-byte field. If a name doesn’t fit, the field can contain:

```
/<decimal_offset>
```

Which means the *real* name is at `<decimal_offset>` inside the *COFF* string table.



### 4.2 Imports / Exports

![image-20251218234846969](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218234846969.png)



#### 4.2.1 KERNEL32.dll

![image-20251218234918441](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218234918441.png)

Nothing immediately stands out as any obvious signs of anti-debugging.



#### 4.2.2 msvcrt.dll

| <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218235520758.png" alt="image-20251218235520758" style="zoom: 80%;" />| <img src="C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251218235552711.png" alt="image-20251218235552711" style="zoom: 80%;" />





---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x64dbg* yields no immediate or obvious signs of any anti-debugging logic.



### 5.2 String Driven-Entry

Searching for string references within the target *Portable Executable* (*PE*) yields results the following results.

![image-20251219002238951](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219002238951.png)

Double clicking on the string reference for "*Enter PIN:* " brings me into the disassembly view where I start to poke and prod around. It seems that it landed me in the `main` function of the *PE*.

![image-20251219002356441](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219002356441.png)

What catches my eye instantly is the `cmp eax, 2179` instruction. Plugging in `0x2179` into my calculator converts the value into decimal, `8569`. Inputting `8569` into the command application yields the following results.

![image-20251219002521559](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219002521559.png)



---

## 6. Validation Path

Once execution reaches `main`, the program follows a very straight-line “prompt", read, compare, branch” flow.



1. **Prompting the user**

   - The program first prints the prompt string:

     - `lea rax, [Enter PIN: ]`

     - `mov rcx, rax`

     - `call 0x...2010`


   - This is the typical “load address of string, pass as first argument, call print” pattern (likely `printf`/`puts` through a wrapper).

------

2. **Reading the input**

- Input is stored into a local stack variable at `[rbp-4]`:

  - `mov dword ptr [rbp-4], 0`   = Initializes the local integer to 0.

  - `lea rax, [rbp-4]`   = Takes the address of that integer.

  - `lea rcx, ["%d"]`  
    Loads the format string for an integer.

  - `mov rdx, rax`

  - `call 0x...2090`


- This matches the typical `scanf("%d", &pin)` calling pattern (format string + pointer to where the integer will be written).

------

3. **The actual check (the entire crackme)**

- After the read, it loads the entered PIN into `EAX` and compares it against a constant:

  - `mov eax, dword ptr [rbp-4]`

  - `cmp eax, 0x2179`

  - `jne fail`


- If the compare succeeds (ZF=1), execution falls through into the success message path. Otherwise, `jne` jumps to the failure message.

- Converting the constant: `0x2179` (hex) = `8569` (decimal).
  So the required PIN is simply `8569`.

------

4. **Success vs failure output**

- **Success path:**

  - Prints `"Correct! by NullerF"`

  - Jumps over the failure block to the common exit.


- **Failure path:**
  - Prints `"Incorrect :/"`


------

5. **Common exit**

- Both paths converge and the program calls `_getch()` to pause before exiting, then returns `0`.



---

## 7. Conclusion

This crackme ultimately demonstrated a very direct control-flow path: prompt, read integer, compare, branch. Despite the unusual *PE* section layout and *COFF* string-table quirks, the executable contained no real obfuscation, anti-debugging, or indirect validation logic. A simple string-driven entry point search led straight into `main`, where the core logic boiled down to a single comparison against the constant `0x2179` (decimal `8569`).

Reaching this point required nothing more than standard tooling. *CFF Explorer* for structural inspection and *x64dbg* for dynamic tracing. The lesson here is that even when a binary *looks* noisy or intentionally odd, fundamentals still win: follow the strings, follow the calls, and verify assumptions in the debugger.

Overall, this challenge was a clean, beginner-friendly exercise in building confidence with string-guided navigation, stack-based input handling analysis, and validating key-check constants in a 64-bit Windows binary. A good warm-up before tackling more complex control-flow, layered checks, or anti-debug-protected crackmes.