# lendigs - C++ idk — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/68ff68d62d267f28f69b78e3  
**Author:** *lendigs*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 1.8 | 3.2 | x86-64 | C/C++ |

---

## Cover Snapshot

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy  

---

[TOC]

---

## 1. Executive Summary

This *crackme* is a straightforward but well-structured console challenge that validates a user-supplied password. The binary contains no packing, obfuscation, or anti-debug measures, allowing direct observation of stack initialization, immediate constant loading, C++ std::string operations, and multiple helper functions leading to the extraction of a hard-coded password string.

During analysis, a suspicious-looking constant array placed on the stack (`a#l67’gdb`) initially appeared to be the key, but further tracing revealed a deeper string transformation path. Following the execution flow of the password-handling functions ultimately exposed the correct computed value. 

<details>
  <summary>Click to reveal password</summary>
	<p>
        	4v9cbr217
    </p>
</details>

Stepping through the internal comparison function confirmed this string as the exact value checked against user input. The binary accepted this value, completing the challenge successfully.



---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs: **Accepts user input for a password.**
- Outputs: *"Enter password: ", "Access denied.", "Access granted."*



### 2.2 Screens

#### Start-up

![image-20251225010509175](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010509175.png)

#### Failure case

![image-20251225010528498](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010528498.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*
- Static tools: *CFF Explorer*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251225010746108](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010746108.png)

The *PE* section table looks like a standard 64-bit *MSVC* debug build with no signs of packing or obfuscation. Code lives in `.textbss` / `.text` (readable + executable), constants and string literals in `.rdata`, and writable globals in `.data`. `.pdata` and `.reloc` provide normal *x64* exception/unwind and relocation info, while `.idata` holds the import table for the *CRT* and *Windows APIs*. Extra sections like `.msvcjmc` and `.00cfg` come from Visual Studio’s debug/runtime features and *Control Flow Guard* configuration. Overall the layout is clean, contiguous, and exactly what you’d expect from an uncomplicated console *crackme* compiled in a debug configuration.



### 4.2 Imports / Exports

![image-20251225010805546](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010805546.png)



#### 4.2.1 MSVCP140D.dll

![image-20251225010911105](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010911105.png)

This import table is full of demangled *C++* standard-library symbols (`std::basic_istream`, `std::basic_ostream`, streambuf/ios_base, locale and exception helpers, etc), which confirms this *crackme* is a *C++* console program built with the *MSVC* debug runtime. The heavy use of iostream and locale/stream machinery lines up with what we see dynamically: the program uses `std::cout`/`std::cin`-style printing and input to prompt for the password, then relies on standard *C++* string and stream operations inside the validation logic rather than raw *WinAPI* calls.



#### 4.2.2 VCRUNTIME140D.dll

![image-20251225011035191](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225011035191.png)



#### 4.2.3 VCRUNTIME140D_1D.dll

![image-20251225011046691](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225011046691.png)



#### 4.2.4 ucrtbased.dll

![image-20251225011115013](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225011115013.png)

![image-20251225011126650](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225011126650.png)



#### 4.2.5 KERNEL32.dll

![image-20251225011209172](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225011209172.png)



---

## 5. Dynamic Analysis

### 5.1 Baseline Run

Starting the program in *x64dbg* yields no immediate or obvious signs of any anti-debugging logic.

### 5.2 String Driven-Entry

Searching for string references within the target *Portable Executable* (*PE*) yields the following results.

![image-20251225040916301](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225040916301.png)

I make note of the following interesting references that I seen output onto the console from the [target overview](###2.2 Screens), "Enter password: ", "*Access denied.*", and based on assumption "*Access granted.*" - which we haven't seen yet.

![image-20251225041533346](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041533346.png)

![image-20251225041400317](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041400317.png)

Double clicking on the string reference for "*Enter password:* " brings me into the disassembly view where I start to poke and prod around. I land on what seems to be the `main` function.

```assembly
00007FF7282D82A0 | 40:55                    | push rbp                                |
00007FF7282D82A2 | 57                       | push rdi                                |
00007FF7282D82A3 | 48:81EC F8010000         | sub rsp,1F8                             |
00007FF7282D82AA | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FF7282D82AF | 48:8D7C24 20             | lea rdi,qword ptr ss:[rsp+20]           |
00007FF7282D82B4 | B9 46000000              | mov ecx,46                              | 46:'F'
00007FF7282D82B9 | B8 CCCCCCCC              | mov eax,CCCCCCCC                        |
00007FF7282D82BE | F3:AB                    | rep stosd                               |
00007FF7282D82C0 | 48:8B05 79ED0000         | mov rax,qword ptr ds:[7FF7282E7040]     | rax:EntryPoint
00007FF7282D82C7 | 48:33C5                  | xor rax,rbp                             | rax:EntryPoint
00007FF7282D82CA | 48:8985 C8010000         | mov qword ptr ss:[rbp+1C8],rax          | rax:EntryPoint
00007FF7282D82D1 | 48:8D0D 9F4D0100         | lea rcx,qword ptr ds:[7FF7282ED077]     |
00007FF7282D82D8 | E8 FE93FFFF              | call crackmes.7FF7282D16DB              |
00007FF7282D82DD | 90                       | nop                                     |
00007FF7282D82DE | C645 08 61               | mov byte ptr ss:[rbp+8],61              | 61:'a'
00007FF7282D82E2 | C645 09 23               | mov byte ptr ss:[rbp+9],23              | 23:'#'
00007FF7282D82E6 | C645 0A 6C               | mov byte ptr ss:[rbp+A],6C              | 6C:'l'
00007FF7282D82EA | C645 0B 36               | mov byte ptr ss:[rbp+B],36              | 36:'6'
00007FF7282D82EE | C645 0C 37               | mov byte ptr ss:[rbp+C],37              | 37:'7'
00007FF7282D82F2 | C645 0D 27               | mov byte ptr ss:[rbp+D],27              | 27:'''
00007FF7282D82F6 | C645 0E 67               | mov byte ptr ss:[rbp+E],67              | 67:'g'
00007FF7282D82FA | C645 0F 64               | mov byte ptr ss:[rbp+F],64              | 64:'d'
00007FF7282D82FE | C645 10 62               | mov byte ptr ss:[rbp+10],62             | 62:'b'
00007FF7282D8302 | 48:C745 38 09000000      | mov qword ptr ss:[rbp+38],9             | 09:'\t'
00007FF7282D830A | C645 54 55               | mov byte ptr ss:[rbp+54],55             | 55:'U'
00007FF7282D830E | 41:B1 55                 | mov r9b,55                              | 55:'U'
00007FF7282D8311 | 41:B8 09000000           | mov r8d,9                               | 09:'\t'
00007FF7282D8317 | 48:8D55 08               | lea rdx,qword ptr ss:[rbp+8]            | rdx:EntryPoint
00007FF7282D831B | 48:8D4D 78               | lea rcx,qword ptr ss:[rbp+78]           |
00007FF7282D831F | E8 EC90FFFF              | call crackmes.7FF7282D1410              |
00007FF7282D8324 | 90                       | nop                                     |
00007FF7282D8325 | 48:8D8D B8000000         | lea rcx,qword ptr ss:[rbp+B8]           |
00007FF7282D832C | E8 9B93FFFF              | call crackmes.7FF7282D16CC              |
00007FF7282D8331 | 90                       | nop                                     |
00007FF7282D8332 | 48:8D15 57B30000         | lea rdx,qword ptr ds:[7FF7282E3690]     | rdx:EntryPoint, 00007FF7282E3690:"Enter password: "
00007FF7282D8339 | 48:8B0D 282E0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D8340 | E8 7E8DFFFF              | call crackmes.7FF7282D10C3              |
00007FF7282D8345 | 90                       | nop                                     |
00007FF7282D8346 | 48:8D95 B8000000         | lea rdx,qword ptr ss:[rbp+B8]           | rdx:EntryPoint
00007FF7282D834D | 48:8B0D EC2E0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D8354 | E8 D48CFFFF              | call crackmes.7FF7282D102D              |
00007FF7282D8359 | 90                       | nop                                     |
00007FF7282D835A | 48:8D55 78               | lea rdx,qword ptr ss:[rbp+78]           | rdx:EntryPoint
00007FF7282D835E | 48:8D8D B8000000         | lea rcx,qword ptr ss:[rbp+B8]           |
00007FF7282D8365 | E8 678EFFFF              | call crackmes.7FF7282D11D1              |
00007FF7282D836A | 0FB6C0                   | movzx eax,al                            |
00007FF7282D836D | 85C0                     | test eax,eax                            |
00007FF7282D836F | 74 26                    | je crackmes.7FF7282D8397                |
00007FF7282D8371 | 48:8D15 30B30000         | lea rdx,qword ptr ds:[7FF7282E36A8]     | rdx:EntryPoint, 00007FF7282E36A8:"Access granted."
00007FF7282D8378 | 48:8B0D E92D0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D837F | E8 3F8DFFFF              | call crackmes.7FF7282D10C3              |
00007FF7282D8384 | 48:8D15 C58CFFFF         | lea rdx,qword ptr ds:[7FF7282D1050]     | rdx:EntryPoint
00007FF7282D838B | 48:8BC8                  | mov rcx,rax                             | rax:EntryPoint
00007FF7282D838E | FF15 F42D0100            | call qword ptr ds:[<public: class std:: |
00007FF7282D8394 | 90                       | nop                                     |
00007FF7282D8395 | EB 24                    | jmp crackmes.7FF7282D83BB               |
00007FF7282D8397 | 48:8D15 22B30000         | lea rdx,qword ptr ds:[7FF7282E36C0]     | rdx:EntryPoint, 00007FF7282E36C0:"Access denied."
00007FF7282D839E | 48:8B0D C32D0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D83A5 | E8 198DFFFF              | call crackmes.7FF7282D10C3              |
00007FF7282D83AA | 48:8D15 9F8CFFFF         | lea rdx,qword ptr ds:[7FF7282D1050]     | rdx:EntryPoint
00007FF7282D83B1 | 48:8BC8                  | mov rcx,rax                             | rax:EntryPoint
00007FF7282D83B4 | FF15 CE2D0100            | call qword ptr ds:[<public: class std:: |
00007FF7282D83BA | 90                       | nop                                     |
00007FF7282D83BB | 48:8D0D 12B30000         | lea rcx,qword ptr ds:[7FF7282E36D4]     | 00007FF7282E36D4:"pause"
00007FF7282D83C2 | FF15 E8300100            | call qword ptr ds:[<system>]            |
00007FF7282D83C8 | 90                       | nop                                     |
00007FF7282D83C9 | C785 B4010000 00000000   | mov dword ptr ss:[rbp+1B4],0            |
00007FF7282D83D3 | 48:8D8D B8000000         | lea rcx,qword ptr ss:[rbp+B8]           |
00007FF7282D83DA | E8 618DFFFF              | call crackmes.7FF7282D1140              |
00007FF7282D83DF | 90                       | nop                                     |
00007FF7282D83E0 | 48:8D4D 78               | lea rcx,qword ptr ss:[rbp+78]           |
00007FF7282D83E4 | E8 578DFFFF              | call crackmes.7FF7282D1140              |
00007FF7282D83E9 | 8B85 B4010000            | mov eax,dword ptr ss:[rbp+1B4]          |
00007FF7282D83EF | 8BF8                     | mov edi,eax                             |
00007FF7282D83F1 | 48:8D4D E0               | lea rcx,qword ptr ss:[rbp-20]           |
00007FF7282D83F5 | 48:8D15 A4AD0000         | lea rdx,qword ptr ds:[7FF7282E31A0]     | rdx:EntryPoint
00007FF7282D83FC | E8 C291FFFF              | call crackmes.7FF7282D15C3              |
00007FF7282D8401 | 8BC7                     | mov eax,edi                             |
00007FF7282D8403 | 48:8B8D C8010000         | mov rcx,qword ptr ss:[rbp+1C8]          |
00007FF7282D840A | 48:33CD                  | xor rcx,rbp                             |
00007FF7282D840D | E8 368FFFFF              | call crackmes.7FF7282D1348              |
00007FF7282D8412 | 48:8DA5 D8010000         | lea rsp,qword ptr ss:[rbp+1D8]          |
00007FF7282D8419 | 5F                       | pop rdi                                 |
00007FF7282D841A | 5D                       | pop rbp                                 |
00007FF7282D841B | C3                       | ret                                     |
```



---

## 6. Validation Path

Right off the bat I notice a constant being loaded onto the stack.

```assembly
00007FF7282D82DE | C645 08 61               | mov byte ptr ss:[rbp+8],61              | 61:'a'
00007FF7282D82E2 | C645 09 23               | mov byte ptr ss:[rbp+9],23              | 23:'#'
00007FF7282D82E6 | C645 0A 6C               | mov byte ptr ss:[rbp+A],6C              | 6C:'l'
00007FF7282D82EA | C645 0B 36               | mov byte ptr ss:[rbp+B],36              | 36:'6'
00007FF7282D82EE | C645 0C 37               | mov byte ptr ss:[rbp+C],37              | 37:'7'
00007FF7282D82F2 | C645 0D 27               | mov byte ptr ss:[rbp+D],27              | 27:'''
00007FF7282D82F6 | C645 0E 67               | mov byte ptr ss:[rbp+E],67              | 67:'g'
00007FF7282D82FA | C645 0F 64               | mov byte ptr ss:[rbp+F],64              | 64:'d'
00007FF7282D82FE | C645 10 62               | mov byte ptr ss:[rbp+10],62             | 62:'b'
00007FF7282D8302 | 48:C745 38 09000000      | mov qword ptr ss:[rbp+38],9             | 09:'\t'
00007FF7282D830A | C645 54 55               | mov byte ptr ss:[rbp+54],55             | 55:'U'
00007FF7282D830E | 41:B1 55                 | mov r9b,55                              | 55:'U'
00007FF7282D8311 | 41:B8 09000000           | mov r8d,9                               | 09:'\t'
```

Specifically focusing on the offsets `+0x8` - `+0xF`, which seems to load the bytes `61 23 6C 36 37 27 67 64 62` == `a # l 6 7 ' g d b`, `a#l67'gdb` without the spaces added for readability.
Due to how strange and suspicious looking this sequence of bytes looks, I decide to plug it in as the password and see if it could be the flag.

![image-20251225042426524](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225042426524.png)

It's not going to be that easy it seems!
What about, backwards - `bdg'76l#a`?

![image-20251225044551221](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225044551221.png)

Womp womp womp!
With the horsing around out of the way, I start further analysing the `main` function.

Here we can see the logic that outputs "*Enter password:* " to the console.

```assembly
00007FF7282D8332 | 48:8D15 57B30000         | lea rdx,qword ptr ds:[7FF7282E3690]     | 00007FF7282E3690:"Enter password: "
00007FF7282D8339 | 48:8B0D 282E0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D8340 | E8 7E8DFFFF              | call crackmes.7FF7282D10C3              |
```

Followed by a call that retrieves the user input from the console.

```assembly
00007FF7282D8346 | 48:8D95 B8000000         | lea rdx,qword ptr ss:[rbp+B8]           |
00007FF7282D834D | 48:8B0D EC2E0100         | mov rcx,qword ptr ds:[<class std::basic |
00007FF7282D8354 | E8 D48CFFFF              | call crackmes.7FF7282D102D              | get input from user
```

Which is then proceeded by what I think is the comparison function.

```assembly
00007FF7282D835A | 48:8D55 78               | lea rdx,qword ptr ss:[rbp+78]           |
00007FF7282D835E | 48:8D8D B8000000         | lea rcx,qword ptr ss:[rbp+B8]           |
00007FF7282D8365 | E8 678EFFFF              | call crackmes.7FF7282D11D1              |
```

Stepping into the comparison function reveals the following assembly.

```assembly
00007FF7282D3D70 | 48:895424 10             | mov qword ptr ss:[rsp+10],rdx           |
00007FF7282D3D75 | 48:894C24 08             | mov qword ptr ss:[rsp+8],rcx            | 
00007FF7282D3D7A | 55                       | push rbp                                |
00007FF7282D3D7B | 57                       | push rdi                                |
00007FF7282D3D7C | 48:81EC E8000000         | sub rsp,E8                              |
00007FF7282D3D83 | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FF7282D3D88 | 48:8D0D C9920100         | lea rcx,qword ptr ds:[7FF7282ED058]     |
00007FF7282D3D8F | E8 47D9FFFF              | call crackmes.7FF7282D16DB              |
00007FF7282D3D94 | 90                       | nop                                     |
00007FF7282D3D95 | 48:8B95 E8000000         | mov rdx,qword ptr ss:[rbp+E8]           |
00007FF7282D3D9C | 48:8B8D E0000000         | mov rcx,qword ptr ss:[rbp+E0]           |
00007FF7282D3DA3 | E8 07D8FFFF              | call crackmes.7FF7282D15AF              |
00007FF7282D3DA8 | 48:8DA5 C8000000         | lea rsp,qword ptr ss:[rbp+C8]           |
00007FF7282D3DAF | 5F                       | pop rdi                                 |
00007FF7282D3DB0 | 5D                       | pop rbp                                 |
00007FF7282D3DB1 | C3                       | ret                                     |
```

 Which appears to make a few more function calls of importance, `call crackmes.7FF7282D15AF`.

```assembly
00007FF7282D6DF0 | 48:895424 10             | mov qword ptr ss:[rsp+10],rdx           |
00007FF7282D6DF5 | 48:894C24 08             | mov qword ptr ss:[rsp+8],rcx            |
00007FF7282D6DFA | 55                       | push rbp                                |
00007FF7282D6DFB | 57                       | push rdi                                |
00007FF7282D6DFC | 48:81EC F8000000         | sub rsp,F8                              |
00007FF7282D6E03 | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FF7282D6E08 | 48:8D0D 49620100         | lea rcx,qword ptr ds:[7FF7282ED058]     |
00007FF7282D6E0F | E8 C7A8FFFF              | call crackmes.7FF7282D16DB              |
00007FF7282D6E14 | 90                       | nop                                     |
00007FF7282D6E15 | 48:8B85 F8000000         | mov rax,qword ptr ss:[rbp+F8]           |
00007FF7282D6E1C | 48:8BC8                  | mov rcx,rax                             |
00007FF7282D6E1F | E8 F7A4FFFF              | call crackmes.7FF7282D131B              |
00007FF7282D6E24 | 48:8985 C0000000         | mov qword ptr ss:[rbp+C0],rax           |
00007FF7282D6E2B | 48:8B8D F0000000         | mov rcx,qword ptr ss:[rbp+F0]           |
00007FF7282D6E32 | E8 E4A4FFFF              | call crackmes.7FF7282D131B              |
00007FF7282D6E37 | 48:8B8D F8000000         | mov rcx,qword ptr ss:[rbp+F8]           |
00007FF7282D6E3E | 4C:8B49 18               | mov r9,qword ptr ds:[rcx+18]            |
00007FF7282D6E42 | 48:8B8D C0000000         | mov rcx,qword ptr ss:[rbp+C0]           |
00007FF7282D6E49 | 4C:8BC1                  | mov r8,rcx                              |
00007FF7282D6E4C | 48:8B8D F0000000         | mov rcx,qword ptr ss:[rbp+F0]           |
00007FF7282D6E53 | 48:8B51 18               | mov rdx,qword ptr ds:[rcx+18]           |
00007FF7282D6E57 | 48:8BC8                  | mov rcx,rax                             | rax:"4v9cbr217"
00007FF7282D6E5A | E8 C8A7FFFF              | call crackmes.7FF7282D1627              |
00007FF7282D6E5F | 48:8DA5 D8000000         | lea rsp,qword ptr ss:[rbp+D8]           |
00007FF7282D6E66 | 5F                       | pop rdi                                 |
00007FF7282D6E67 | 5D                       | pop rbp                                 |
00007FF7282D6E68 | C3                       | ret                                     |
```

It seems that `RAX` is `4v9cbr217` after `call crackmes.7FF7282D131B`. I decide to step into that function.

```assembly
00007FF7282D71F0 | 48:894C24 08             | mov qword ptr ss:[rsp+8],rcx            |
00007FF7282D71F5 | 55                       | push rbp                                |
00007FF7282D71F6 | 57                       | push rdi                                |
00007FF7282D71F7 | 48:81EC 08010000         | sub rsp,108                             |
00007FF7282D71FE | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FF7282D7203 | 48:8D0D 4E5E0100         | lea rcx,qword ptr ds:[7FF7282ED058]     |
00007FF7282D720A | E8 CCA4FFFF              | call crackmes.7FF7282D16DB              |
00007FF7282D720F | 90                       | nop                                     |
00007FF7282D7210 | 48:8B85 00010000         | mov rax,qword ptr ss:[rbp+100]          |
00007FF7282D7217 | 48:83C0 08               | add rax,8                               | rax:"4v9cbr217"
00007FF7282D721B | 48:8945 08               | mov qword ptr ss:[rbp+8],rax            | [rbp+08]:"4v9cbr217"
00007FF7282D721F | 48:8B8D 00010000         | mov rcx,qword ptr ss:[rbp+100]          |
00007FF7282D7226 | E8 51A4FFFF              | call crackmes.7FF7282D167C              |
00007FF7282D722B | 0FB6C0                   | movzx eax,al                            |
00007FF7282D722E | 85C0                     | test eax,eax                            |
00007FF7282D7230 | 74 14                    | je crackmes.7FF7282D7246                |
00007FF7282D7232 | 48:8B85 00010000         | mov rax,qword ptr ss:[rbp+100]          |
00007FF7282D7239 | 48:8B48 08               | mov rcx,qword ptr ds:[rax+8]            |
00007FF7282D723D | E8 A8A4FFFF              | call crackmes.7FF7282D16EA              |
00007FF7282D7242 | 48:8945 08               | mov qword ptr ss:[rbp+8],rax            | [rbp+08]:"4v9cbr217"
00007FF7282D7246 | 48:8B45 08               | mov rax,qword ptr ss:[rbp+8]            | [rbp+08]:"4v9cbr217"
00007FF7282D724A | 48:8DA5 E8000000         | lea rsp,qword ptr ss:[rbp+E8]           |
00007FF7282D7251 | 5F                       | pop rdi                                 |
00007FF7282D7252 | 5D                       | pop rbp                                 |
00007FF7282D7253 | C3                       | ret                                     |
```

Which seems to load the bytes `34 76 39 63 62 72 32 31 37` - `4v9cbr217` - and return it, which is looking awfully a lot like the flag.
Stepping back out of the above function, I notice my input `helloworld` being loaded in from `ss:[RBP+F8]` into `RCX` and `4v9cbr217` being loaded into `R8` before the following *call* instruction which seems to do the actual comparison.

```assembly
00007FF7282D6E5A | E8 C8A7FFFF              | call crackmes.7FF7282D1627              |
```



---

## 7. Testing the New Flag

With the dynamic analysis done, I fire up the *crackme* and enter `4v9cbr217` as the flag - password.

![image-20251225153717329](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225153717329.png)

Amazing! Third time's the charm.



---

## 8. *x64dbg* Festive Icon Set

Side note, I just launched *x64dbg* on Christmas Eve and it has a whole other icon set for the holiday!

![image-20251225041007219](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041007219.png)

![image-20251225041124123](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041124123.png)

![image-20251225041136991](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041136991.png)

![image-20251225041153924](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225041153924.png)

*Neato*!



---

## 9. Conclusion

In the end, this crackme was a straightforward C*+*+ console app hiding behind a lot of standard library noise. The section layout and imports made it clear early on that there was no packing or fancy obfuscation going on, just a debug build using *MSVCP* and the usual iostream and string machinery. Once I followed the "*Enter password: *" prompt into `main` and traced the calls that shuffled `std::string` objects around, the real logic basically revealed itself. Stepping through the comparison path in *x64dbg* showed the program constructing the secret string `4v9cbr217` and feeding it into the final check against my input. Typing that in gives a clean "*Access granted.*".
The main takeaway here is that even when the *C++* runtime makes the call graph look busy, sticking to the basics (strings, calls, and comparisons) gets you to the flag without needing any heavy tricks.



The final solution is the recovered password:

```text
4v9cbr217
```