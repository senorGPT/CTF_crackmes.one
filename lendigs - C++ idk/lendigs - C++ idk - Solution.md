# lendigs - C++ idk — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/68ff68d62d267f28f69b78e3  
**Author:** *lendigs*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *x64dbg*, *Binary Ninja*  

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

![image-20251225010509175](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010509175.png)

#### Failure case

![image-20251225010528498](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010528498.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*
- Decompiler: *Binary Ninja*
- Static tools: *CFF Explorer*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251225010746108](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010746108.png)

Notes:
- Architecture:

- Compiler hints:

- Packing/obfuscation signs:

  

### 4.2 Imports / Exports

![image-20251225010805546](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010805546.png)



#### 4.2.1 MSVCP140D.dll

![image-20251225010911105](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251225010911105.png)



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





---

## 7. Patch Notes (If Allowed)



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

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.



---

## Appendix A —  Reference Notes

- Addresses:
- Breakpoints list:
- Useful commands: