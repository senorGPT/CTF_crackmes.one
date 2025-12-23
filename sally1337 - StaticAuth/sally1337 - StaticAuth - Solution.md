# sally1337 - StaticAuth — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/6947f3c00c16072f40f5a2b0  
**Author:** *sally1337*  
**Write-up by:** *SenorGPT*  
**Tools used:** *CFF Explorer*, *Binary Ninja*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 2.0 | 4.0 | x86-64 | C/C++ |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\sally1337 - StaticAuth\cover.png" alt="cover" style="zoom:45%;" /></center>

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



### 1.1 Crackme Description

This is a classic, beginner-friendly reverse engineering challenge designed to teach static analysis techniques. A password is hidden within the binary using simple obfuscation methods. Your task is to analyze the executable ***without running it***, locate the obfuscated data, reconstruct the correct key, and enter it into the program.



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

## 5. Static Analysis

Loading up the *Portable Executable* (*PE*) within Binary Ninja, I begin by targeting the *Symbols*.

![image-20251223174840109](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223174840109.png)

I am trying to find where the entry point is, I try the following common symbols; `entry`, `_start`, and `WinMainCRTStartup`. I get a hit on `_start`.

![image-20251223175024575](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223175024575.png)

Double clicking it opens up the `_start` function in the *High Level IL* view.

![image-20251223175126948](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251223175126948.png)

*Binary Ninja* labels auto functions starting with the prefix `sub_`, the first function is just *C Run Time* (*CRT*) and initialization code. Double clicking on `__scrt_common_main_seh` lands me in that function where there should be a call to the `main` function somewhere.

```c
1400028a7        if (__scrt_initialize_crt(1) == 0)
1400029e8            sub_140002dcc(7)
1400029e8            noreturn
1400029e8        
1400028ad        int64_t rsi
1400028ad        rsi.b = 0
1400028b0        char var_18 = 0
1400028ba        int64_t rbx
1400028ba        rbx.b = __scrt_acquire_startup_lock()
1400028bc        int32_t rcx = data_140006120
1400028bc        
1400028c5        if (rcx == 1)
1400029f3            sub_140002dcc(7)
1400029f3            noreturn
1400029f3        
1400028cd        if (rcx != 0)
140002919            rsi.b = 1
14000291c            char var_18_1 = 1
1400028cd        else
1400028cf            data_140006120 = 1
1400028cf            
1400028ee            if (_initterm_e(_First: &data_140004298, _Last: &data_1400042b0) != 0)
1400028f0                return 0xff
1400028f0            
140002908            _initterm(_First: &data_140004280, _Last: &data_140004290)
14000290d            data_140006120 = 2
14000290d        
140002921        rcx.b = rbx.b
140002923        __scrt_release_startup_lock(rcx.b)
140002923        
140002934        if (data_1400061a8 != 0
140002934                && __scrt_is_nonwritable_in_current_image(&data_1400061a8) != 0)
14000294e            data_1400061a8(0, 2, 0)
14000294e        
140002960        if (data_1400061a0 != 0
140002960                && __scrt_is_nonwritable_in_current_image(&data_1400061a0) != 0)
140002971            _register_thread_local_exe_atexit_callback(_Callback: data_1400061a0)
140002971        
140002976        _get_initial_narrow_environment()
140002983        *__p___argv()
140002991        *__p___argc()
140002993        main()
140002993        
1400029a1        if (sub_140002ddc() == 0)
1400029fa            exit(_Except: 0)
1400029fa            noreturn
1400029fa        
1400029a6        if (rsi.b == 0)
1400029a8            _cexit()
1400029a8        
1400029b1        __scrt_uninitialize_crt(1, 0)
1400029b6        return 0
```

Bingo!

```c
140002993        main()
```

Double clicking it lands us in `main`.

```c
140001d57        void var_a8
140001d57        int64_t rax_1 = __security_cookie ^ &var_a8
140001d60        int32_t var_88 = 0
140001d71        sub_140002050(std::cout, "System authentication required.\n")
140001d76        int32_t r15 = 3
140001d7c        int64_t r14
140001d7c        r14.b = 0
140001d7c        
140001d83        while (r14.b == 0)
140001d97            sub_140002050(std::cout, "\nEnter authentication code: ")
140001da0            int128_t var_80 = zx.o(0)
140001da4            char* rbx_1 = nullptr
140001da6            char* var_70_1 = nullptr
140001daa            int64_t rdi_1 = 0xf
140001daf            int64_t var_68_1 = 0xf
140001db3            var_80.b = 0
140001db9            int32_t var_88_1 = 1
140001dbc            char i_2
140001dbc            int64_t rdx_1
140001dbc            int64_t r8_1
140001dbc            i_2, rdx_1, r8_1 = _getch()
140001dc2            char i_1 = i_2
140001dc2            
140001dc6            if (i_2 != 0xd)
140001e5e                char i
140001e5e                
140001e5e                do
140001dd3                    if (i_1 != 8)
140001e0c                        if (i_1 - 0x20 u<= 0x5e)
140001e11                            if (rbx_1 u>= rdi_1)
140001e3a                                sub_140002560(&var_80, rdx_1, r8_1, i_1)
140001e11                            else
140001e17                                var_70_1 = &rbx_1[1]
140001e1b                                char* rax_5 = &var_80
140001e1b                                
140001e23                                if (rdi_1 u> 0xf)
140001e23                                    rax_5 = var_80.q
140001e23                                
140001e28                                *(rax_5 + rbx_1) = i_1
140001e2b                                *(rax_5 + rbx_1 + 1) = 0
140001e2b                            
140001e46                            sub_140002220(std::cout)
140001e4b                            rbx_1 = var_70_1
140001e4f                            rdi_1 = var_68_1
140001dd3                    else if (rbx_1 != 0)
140001ddd                        var_70_1 = rbx_1 - 1
140001de1                        int128_t* rax_2 = &var_80
140001de1                        
140001de9                        if (rdi_1 u> 0xf)
140001de9                            rax_2 = var_80.q
140001de9                        
140001dee                        *(rbx_1 - 1 + rax_2) = 0
140001e00                        sub_140002050(std::cout, &data_1400043a0)
140001e4b                        rbx_1 = var_70_1
140001e4f                        rdi_1 = var_68_1
140001e4f                    
140001e53                    i, rdx_1, r8_1 = _getch()
140001e59                    i_1 = i
140001e5e                while (i != 0xd)
140001e5e            
140001e72            std::ostream::operator<<(this: std::cout, sub_1400023f0)
140001e7c            int128_t var_60
140001e7c            sub_1400015b0(&var_60)
140001e88            int64_t var_50
140001e88            char* rbx_3
140001e88            int64_t var_48
140001e88            
140001e88            if (rbx_1 == var_50)
140001ece                int64_t rdx_5 = 0
140001ed0                rbx_3 = var_80.q
140001ed8                int128_t* r8_2 = var_60.q
140001ed8                
140001edf                if (var_50 == 0)
140001f1d                label_140001f1d:
140001f1d                    
140001f21                    if (var_48 u<= 0xf)
140001f54                        r14.b = 1
140001f57                        sub_140001ae0()
140001f21                    else
140001f2e                        if (var_48 + 1 u>= 0x1000)
140001f30                            int128_t* rax_9 = *(r8_2 - 8)
140001f30                            
140001f3f                            if (r8_2 - rax_9 - 8 u> 0x1f)
140002038                                trap(0xd)
140002038                            
140001f49                            r8_2 = rax_9
140001f49                        
140001f4f                        sub_140002774(_Block: r8_2)
140001f54                        r14.b = 1
140001f57                        sub_140001ae0()
140001edf                else
140001ef0                    while (true)
140001ef0                        char* rcx_10 = &var_80
140001ef0                        
140001ef8                        if (rdi_1 u> 0xf)
140001ef8                            rcx_10 = rbx_3
140001ef8                        
140001efc                        int128_t* rax_7 = &var_60
140001efc                        
140001f04                        if (var_48 u> 0xf)
140001f04                            rax_7 = r8_2
140001f04                        
140001f0f                        if (rcx_10[rdx_5] != *(rax_7 + rdx_5))
140001f0f                            break
140001f0f                        
140001f15                        rdx_5 += 1
140001f15                        
140001f1b                        if (rdx_5 u>= var_50)
140001f1b                            goto label_140001f1d
140001f1b                    
140001fe9                    if (var_48 u<= 0xf)
140002018                        r15 -= 1
140002029                        sub_140002050(std::cout, "Authentication failed.\n")
140001fe9                    else
140001ff6                        if (var_48 + 1 u>= 0x1000)
140001ff8                            int128_t* rax_12 = *(r8_2 - 8)
140001ff8                            
140002007                            if (r8_2 - rax_12 - 8 u> 0x1f)
140002038                                trap(0xd)
140002038                            
14000200d                            r8_2 = rax_12
14000200d                        
140002013                        sub_140002774(_Block: r8_2)
140002018                        r15 -= 1
140002029                        sub_140002050(std::cout, "Authentication failed.\n")
140001e88            else
140001e92                if (var_48 u> 0xf)
140001e97                    void* rcx_7 = var_60.q
140001e97                    
140001ea2                    if (var_48 + 1 u>= 0x1000)
140001ea4                        void* rax_6 = *(rcx_7 - 8)
140001ea4                        
140001eb3                        if (rcx_7 - rax_6 - 8 u> 0x1f)
140002038                            trap(0xd)
140002038                        
140001ebd                        rcx_7 = rax_6
140001ebd                    
140001ec0                    sub_140002774(_Block: rcx_7)
140001ec0                
140001ec5                rbx_3 = var_80.q
140002018                r15 -= 1
140002029                sub_140002050(std::cout, "Authentication failed.\n")
140002029            
140001f63            if (rdi_1 u> 0xf)
140001f70                if (rdi_1 + 1 u>= 0x1000)
140001f72                    char* rax_10 = *(rbx_3 - 8)
140001f72                    
140001f81                    if (rbx_3 - rax_10 - 8 u> 0x1f)
14000203f                        trap(0xd)
14000203f                    
140001f8b                    rbx_3 = rax_10
140001f8b                
140001f91                sub_140002774(_Block: rbx_3)
140001f91            
140001f99            if (r15 s<= 0)
140001fa2                if (r14.b == 0)
140001fb2                    sub_140002050(std::cout, "\nMaximum attempts reached.\n")
140001fc5                    sub_140002050(std::cout, "System locked.\n")
140001fc5                
140001fa2                break
140001fa2        
140001fd3        __security_check_cookie(rax_1 ^ &var_a8)
140001fe4        return 0

```



Analysing the code I can see that upon running it we should be greeted with the following messages where it prompts us for an authentication code.

```bash
System authentication required

Enter authentication code: 
```





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