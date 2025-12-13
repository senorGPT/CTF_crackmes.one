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

### 2.1 UI / Behaviour

- Inputs: *Musukkan password:* 
- Outputs: *Password salah.*

### 2.2 Screens

#### Start-up

![image-20251211213227068](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211213227068.png)

#### Failure Case - Followed by Termination

Note: when the password is entered - `helloworld` - it is hidden.

![image-20251211213321389](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211213321389.png)



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Debugger: *x64dbg*

- Static tools: *CFF Explorer, Detect It Easy (DIE)*



---

## 4. Static Recon

### 4.1 File & Headers

![image-20251211214216692](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211214216692.png)

**Architecture:**

- PE32+ (64-bit) Windows executable with a standard x64 section layout: `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`.

**Compiler hints**:

- Nothing suggests a custom linker or unusual toolchain

**Packing/obfuscation signs:**

- Multiple well-formed sections with reasonable raw/virtual sizes; `.text` is not tiny compared to the whole file. No suspicious sections (e.g. `.UPX`, `.packed`, random names) and no single huge “blob” section.



### 4.2 Imports / Exports

![image-20251211214230874](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211214230874.png)

**Imported modules:**

- `USER32.dll` (14 functions) – typical GUI / message-box and basic user-interaction APIs.
- `KERNEL32.dll` (110 functions) – main workhorse for this crackme: process & memory management, file/console I/O, timing, and potential anti-debug helpers.
- `ADVAPI32.dll` (4 functions) – a few advanced *WinAPI* calls (e.g. registry/privilege/crypto–related), but only a small set is used.



#### 4.2.1 USER32.dll

Upon second analysis after my typical `KERNEL32.dll` breakpoints for input were leading nowhere, I took another look at the modules imported and what functions were being used.

![image-20251211231958303](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251211231958303.png)

Those imports are the classic Win32 message-loop toolkit:

- `CreateWindowExW`, `RegisterClassW`, `ShowWindow`, `DestroyWindow`
   Create/show/destroy a window. Indicates it might be creating a *hidden GUI window*.
- `GetMessageW` / `PeekMessageW` / `DispatchMessageW` / `TranslateMessage`
  This is the *message loop*. These functions pull messages (like `WM_KEYDOWN`, `WM_CHAR`, mouse events, etc.) out of the queue and send them to the window procedure. That’s where keyboard input would actually be handled.
- `DefWindowProcW`, `SetWindowLongPtrW`, `GetWindowLongPtrW`
   Default message handling and installing/retrieving a custom window procedure (`WndProc`) where user input is processed.

This *PE* could absolutely be capturing keyboard input by handling `WM_CHAR` / `WM_KEYDOWN` in its window procedure, fed by `GetMessageW`/`PeekMessageW`.



Side note: it seems that the language used is *Indonesian*.



---

## 5. Dynamic Analysis

Starting the program in *x64dbg* yields no immediate or obvious signs of anti-debugging logic.



### 5.1 String-Driven Entry

Upon searching for string references, it seems that the strings might be encoded as I was unable to find any references to the strings "*Masukkan password:* " and "*Password salah.*".



### 5.2 Input Breakpoints

#### 5.2.1 KERNEL32.DLL Input Breakpoints

 I decide to start with breakpoints that might be used for obtaining the user input from the console;

| Function            | Reason for Interest                                          |
| ------------------- | ------------------------------------------------------------ |
| `ReadConsoleA/W`    | Catches direct keyboard input from the console,can see exactly where the program reads the name/serial and what buffer it lands in. |
| `WriteConsoleA/W`   | Hits when the program prints prompts or messages; stepping right after often leads straight into the input and validation flow. |
| `ReadFile`          | Many console apps read `STDIN` via a handle as if it were a file, so this is a reliable fallback when `ReadConsoleA/W` isn’t used. |
| `WriteFile`         | Console output is sometimes routed through file-style writes, so it helps catch prompts and trace the execution path around user interaction. |
| `GetStdHandle`      | Usually called right before `ReadConsoleA/W`/`ReadFile` or output calls, so it’s a great “early warning” breakpoint for the I/O path. |
| `GetCommandLineA/W` | Useful when input is passed as command-line args; you can see raw input early before it gets parsed or transformed. Doesn't seem necessary for this *PE* as it doesn't appear to use command line arguements, although it does not hurt to add it. |
| `GetProcAddress`    | Reveals dynamically resolved APIs (often hidden checks or *CRT* - C Runtime - calls); the requested function name can instantly expose the program’s real strategy. |

For those that are following along, here is an *x64dbg* command to add all these breakpoints:

```c
bp kernel32.ReadConsoleW; bp kernel32.ReadConsoleA; bp kernel32.WriteConsoleW; bp kernel32.WriteConsoleA; bp kernel32.ReadFile; bp kernel32.WriteFile; bp kernel32.GetStdHandle; bp kernel32.GetCommandLineA; bp kernel32.GetCommandLineW; bp kernel32.GetProcAddress
```



Upon entering my input value of `helloworld` and hitting enter none of my breakpoints get triggered.
I add *six more* breakpoints onto functions from `kernel32.dll`.

| Function              | Reason for Interest                                          |
| --------------------- | ------------------------------------------------------------ |
| `GetConsoleMode`      | Lets the program query current console flags (like `ENABLE_ECHO_INPUT` and `ENABLE_LINE_INPUT`); seeing this call right before input strongly hints it’s about to tweak how keyboard input is handled (e.g., turning echo off for a hidden password). |
| `SetConsoleMode`      | Used to change console input mode flags; if you see it clear `ENABLE_ECHO_INPUT`, you’ve basically confirmed the binary is intentionally hiding typed characters while still reading them normally. |
| `ReadConsoleInputW`   | Reads low-level input events (key presses, mouse, etc.) rather than simple text lines; hitting this breakpoint suggests the crackme is processing raw key events, which can fully bypass your usual `ReadConsoleA/W` and `ReadFile` breakpoints. |
| `ReadConsoleInputA`   | Same as `ReadConsoleInputW` but ANSI; useful to breakpoint in case the author chose the ANSI variant for raw key event processing or custom input handling. |
| `PeekConsoleInputW/A` | Lets the program inspect pending console input events without consuming them; often used in loops that poll for keys or implement their own “password echo off” logic, so hitting this can drop you right into the custom input-reading loop. |

For those that are following along, here is an *x64dbg* command to add all these breakpoints:

```c
bp kernel32.GetConsoleMode; bp kernel32.SetConsoleMode; bp kernel32.ReadConsoleInputW; bp kernel32.ReadConsoleInputA; bp kernel32.PeekConsoleInputW; bp kernel32.PeekConsoleInputA
```



No hits again.



#### 5.2.2 USER32.DLL Input Breakpoints

I circle back around to the static analysis and take another look at the *Import Directory*, focusing on [USER32.DLL](####4.2.1 USER32.dll).

| Function           | Reason for Interest                                          |
| ------------------ | ------------------------------------------------------------ |
| `RegisterClassW`   | Registers a window class that includes a pointer to the custom *WndProc*; breaking here lets you grab the *WndProc* address where keyboard messages will ultimately be handled. |
| `CreateWindowExW`  | Creates the actual (possibly hidden) window that receives keyboard input; from here you can confirm which *WndProc* is in use and set a breakpoint on it. |
| `GetMessageW`      | Blocks while pulling messages (like `WM_KEYDOWN` / `WM_CHAR`) from the message queue; hitting this shows you when the program enters its main input/event loop. |
| `PeekMessageW`     | Non-blocking version used to poll the message queue; often used in custom loops that process key events manually, so a breakpoint here can drop you right into the program’s own input-processing logic. |
| `DispatchMessageW` | Sends retrieved messages to the *WndProc*; breaking here and stepping into the call will land you inside the window procedure where the *PE* interprets keystrokes and builds the password buffer. |

For those that are following along, here is an *x64dbg* command to add all these breakpoints:

```c
bp user32.RegisterClassW; bp user32.CreateWindowExW; bp user32.GetMessageW; bp user32.PeekMessageW; bp user32.DispatchMessageW;
```



Progress! It seems that on start-up it is calling `RegisterClassW`, `CreateWindowExW`, `DispatchMessageW` in that order once, then repeatedly calls `PeekMEssageW`, I assume on every frame. This is *exactly* what should be expected from a *fake console + hidden window*.



#### 5.2.3 More USER32.DLL Input Breakpoints

All the above breakpoints don't seem to lead me to the validation logic or even the logic where the input is being transferred. I set some more breakpoints on more methods within `USER32.DLL`.

```c
bp user32.GetWindowTextW; bp user32.GetWindowTextA; bp user32.GetDlgItemTextW; bp user32.GetDlgItemTextA; bp user32.SendMessageW; bp user32.SendMessageA;
```



None of these breakpoints seemed to fire upon validation or keyboard input. Which is a big clue in itself. The import list earlier includes `SetWindowLongPtrW` / `GetWindowLongPtrW`, which is exactly what Windows uses to change a window’s **window procedure** (`GWLP_WNDPROC = -4`) or subclass controls (like an EDIT box).

```c
bp user32.SetWindowLongPtrW;
```



I end up going mad with frustration and enabling the following breakpoints as I was running out of ideas:

```c
bp kernel32.WriteConsoleOutputCharacterW; bp kernel32.WriteConsoleOutputCharacterA; bp kernel32.WriteConsoleOutputW; bp kernel32.WriteConsoleOutputA; bp kernel32.WriteConsoleOutputAttribute;
```

```c
bp user32.MessageBoxW; bp user32.MessageBoxA; bp user32.DrawTextW; bp user32.DrawTextA;
```

```c
bp gdi32.TextOutW; bp gdi32.TextOutA; bp gdi32.ExtTextOutW; bp gdi32.ExtTextOutA;
```

```c
bp kernel32.ExitProcess; bp kernel32.TerminateProcess; bp ntdll.RtlExitUserProcess;
```



------

## 6. Entry Strategy

First things first, is to grab the *WndProc* from the `RegisterClassW` call.
View [RegisterClassW](####8.2.1 USER32.DLL.RegisterClassW) for more information on function prototype.

Hitting the `CreateWindowExW` breakpoint, seems to confirm a few things.
View [CreateWindowExW](####8.2.1 USER32.DLL.CreateWindowExW) for more information on function prototype.

I notice that `lpWindowName` = `PyInstaller Onefile Hidden Window`, `nWidth` = 0, and `nHeight` = 0. Confirming that my lead is correct regarding the hidden window.

**TODO - update this part as its not RCX its the pointer at RCX+08**

Breaking on the call to `RegisterClassW` I copy the address in `RCX` - `00000007C37EB8B0` and add a breakpoint on it - `bp 00000007C37EB8B0;`.

![image-20251212003048451](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212003048451.png)

So this WndProc has a tiny `switch (uMsg)`:

- `uMsg == 0x0001` : WM_CREATE
- `uMsg == 0x0011` : WM_QUERYENDSESSION
- `uMsg == 0x0016` : WM_ENDSESSION
- anything else: fall through to `DefWindowProcW`

Notice that `0x0100` (`WM_KEYDOWN`), no `0x0102` (`WM_CHAR`), etc are *missing*. That’s why It does not refire on every keypress, this procedure simply doesn’t care about keyboard messages.

What is most certainly happening is that the window has a child *EDIT control* (or similar). All the keystrokes go to the EDIT control’s own internal *WndProc* (inside `USER32.dll`). When it’s time to validate, the program grabs the full text at once via something like:

- `GetWindowTextW`
- `GetDlgItemTextW`
- `SendMessageW(hEdit, WM_GETTEXT, …)`



Upon initialization, there are three calls made to `SetWindowLongPtrW`.

| RDX              | nIndex                                         | R8                             |
| ---------------- | ---------------------------------------------- | ------------------------------ |
| 00000000FFFFFFFE |                                                | FFFFFFFFFFFFFFFF               |
| 00000000FFFFFFFE |                                                | 000001CDF9CA0DE0               |
| 00000000FFFFFFEB | `GWLP_USERDATA` (–21) - *store custom pointer* | 00007FF7B0163D30 - within *PE* |



Things are starting to get frustrating. Every lead I try goes cold. I attempted finding references based on patterns of my input that I entered, finding patterns of known strings when they appeared, finding string references but everything lead to nothing.

The last thing I can think of before I go take a break is to try going backwards from the termination of the program.



### 6.1 Fresh Mind

After sleeping on it and taking some time away from this *CTF* I came back with a clear mind. That's when it occurred to me. I already know that *PyInstaller* was used to build this *PE*. So given that information I can try to unpack and decompile the binary back to just a *Python* script.



First thing to do is to grab a *PyInstaller Extractor*, I find some on *Github* and settle for [pyinstxtractor by extremecoders-re](https://github.com/extremecoders-re/pyinstxtractor). Cloning the repo and moving the `pyinstxtractor.py` file to the directory of the `PE`.

Running the command `py pyinstxtractor.py guess-password.exe`:

![image-20251212190324686](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212190324686.png)

It worked! Let's see what we're dealing with.

One file I notice that spikes interest right off the bat is `bcrypt`.

![image-20251212190455197](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212190455197.png)

Some other *Python* native extension module files to keep note of:

![image-20251212190428172](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212190428172.png)

The `.pyc` logic files - `check_password.pyc` stands out the most. That must be where the main program logic lives:

![image-20251212190802036](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212190802036.png)



### 6.3 Taking a Peek at the Python

I decide to start with `check_password.pyc`. *But*, before proceeding I need to decompile the Python cross-version byte-code (`.pyc`) file utilizing [decompyle3](https://pypi.org/project/decompyle3/).

First to install `decompyle3` with:

```bash
py -m pip install decompyle3
```

![image-20251212191901027](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212191901027.png)

Strange, let's try another decompiler [uncompyle6](https://pypi.org/project/uncompyle6/):

```bash
py -m pip install uncompyle6
```

![image-20251212192454698](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212192454698.png)

I don't want to waste too much time on why these are failing. I utilize an online tool [pylingual](https://pylingual.io/) and it works perfectly. I download the decompiled *Python* file and open it within *VS Code.*

```python
import bcrypt
import getpass
import sys
STORED_HASH = b'$2b$12$pBRbErJA/R.oPinWBAx4buejz59JCDiARNr07zSRrK/1F8jHpMzSm'

def check_password():
    try:
        pw = getpass.getpass('Masukkan password: ').encode()
    except:
        print('\nGagal membaca input.')
        sys.exit(1)
    try:
        if bcrypt.checkpw(pw, STORED_HASH):
            return True
        return False
    except:
        return False

def main():
    if check_password():
        print('Password benar, akses diberikan.')
        return
    print('Password salah.')
    sys.exit(2)
if __name__ == '__main__':
    main()
```



### 6.4 Breaking Down the Python

Instantly I notice the stored hash as well as the `bcrypt` import which is later being used to encode the user input and check the password.

`bcrypt` is a password-hashing algorithm, since it is *one-way* I doubt I will be able to *decrypt* the stored hash.

It's whole purpose is to turn a password into a stored hash that’s hard to brute-force - slow on purpose -, unique per user thanks to a *salt*, and adjustable in cost so you can make it slower as hardware gets faster. It uses the *Blowfish* cipher’s key schedule internally. Takes a password, a randomly generated *salt*, and a *cost factor* (work factor). Then runs a deliberately expensive computation and outputs a 60-char string, like the `STORED_HASH` in `check_password.py`.

The `STORED_HASH` (`$2b$12$pBRbErJA/R.oPinWBAx4buejz59JCDiARNr07zSRrK/1F8jHpMzSm`) already contains the algorithm/version used (`2b`), the cost (`12`), the *salt*, as well as the *resulting hash*.
When the call to `bcrypt.checkpw(password, stored_hash)` is made, `bcrypt` parses the hash to get the *salt* + *cost* + *digest*.

If the hash matches then the code returns `True`. Which then prints the success branch string `'Password benar, akses diberikan.` (which translates to `Password is correct, access is granted.` in *English*) before terminating the process.



So it seems that my only option is to brute-force the answer. Time to write some *Python* code.



---

## 7. Validation Path

First I have to install [bcrypt]() with:

```bash
py -m pip install bcrypt
```

I whip up some half okay *Python* code that will utilize a word list, as I feel this would be a better spend of resources compared to an exhaustive key search / full brute force.
(I stripped a bunch of code from this version for readability purposes)

```python
def load_candidates(path: Path):
    """Yield password candidates (as bytes) from a wordlist file."""
    with path.open("rb") as f:  # read as bytes so we don't fight encodings
        for line in f:
            line = line.rstrip(b"\r\n")
            if not line:
                continue
            yield line


def brute_force(wordlist_path: Path):
    """Test each candidate against the STORED_HASH."""
    total = 0
    for pw in load_candidates(wordlist_path):
        total += 1
        if bcrypt.checkpw(pw, STORED_HASH):
            print(f"[+] Password FOUND: {pw.decode(errors='replace')!r}")
            return True

        # Optional tiny progress indicator
        if total % 1000 == 0:
            print(f"[.] Tried {total} candidates...", end="\r", flush=True)

    print(f"[-] Exhausted wordlist ({total} candidates), no match.")
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <wordlist.txt>")
        return 1

    wordlist_path = Path(argv[1])
    if not wordlist_path.is_file():
        print(f"[-] Wordlist not found: {wordlist_path}")
        return 1

    try:
        ok = brute_force(wordlist_path)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        return 130

    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

Time to locate some wordlists!
A really good resource for wordlists is [Weakpass](https://weakpass.com/wordlists) as they have a whole section of their website dedicated to hosting different wordlists.
I decide I want to start with the [rockyou.txt](https://weakpass.com/wordlists/rockyou.txt) wordlist, which contains around *14.34 million* passwords! I also add a small list of custom words to a `custom_ctf_wordlist.txt` file that relate specifically to reverse engineering.

<details><summary><strong>Custom CTF / RE Wordlist (click to expand)</strong></summary>ctf
ctf1
ctf123
ctf2024
ctf2025
ctftime
ctfplayer
ctfplayer1
ctfplayer123
capturetheflag
capture_flag
capturetheflag123
capturetheflag2024
flag
flag1
flag123
flag2024
flag{test}
flag{ctf}
flag{crackme}
flag{password}
flag{re}
flag{reverse}
flag{this_is_fake}
flag{guess_me}
flag{not_the_real_flag}
flag{you_got_it}
getflag
get_the_flag
give_me_flag
givemeflag
gimmeflag
where_is_flag
findtheflag
find_flag
flaghunter
flaghunter123
pwn
pwned
pwnme
pwnthis
pwnthisctf
pwn3d
leet
l33t
1337
1337h4x0r
h4x0r
hacker
hacking
reverse
reversing
reverser
reverseme
reverseit
reverseit123
reverse_engineer
reverseengineering
reverseengineering123
rev
rev1
rev2
rev3
rev100
revctf
revchallenge
revchallenge1
revchallenge2
crackme
crackme1
crackme2
crackme3
crackme4
crackme5
crackme2024
crackmes
crackmes1
crackmes2
crackmes3
crackmesone
crackmes_one
crackmesde
crackmes_de
crackmesdotde
crackmesdotone
crackthis
crackthis1
crackthis2
crackthisnow
uncrackable
uncrackable1
uncrackable2
nocrack
reverse_this
reverse_this_please
decryptme
decrypt_me
decrypt_this
decompile_me
decompilethis
debugme
debug_me
debug_this
x64dbg
x32dbg
ida
idapro
ida_free
ghidra
ghidra1
ghidra2
radare
radare2
binaryninja
binja
ollydbg
cheatengine
cheat_engine
nopthis
nop_this
patchme
patch_me
patchthis
patch_this
patchit
patch_it
bruteforce
bruteforce1
bruteforce2
bfattack
dictionaryattack
pyinstaller
pyinst
pycrackme
crackpy
pythoncrackme
ctfcrackme
recrackme
myfirstcrackme
myfirstctf
firstctf
first_crackme
masuk
passwordctf
ctfpassword
ctfpass
ctfpass123
sandi
sandi123
passwordbenar
passwordsalah
benar123
salah123
aksesdiberikan
aksesditolak
letmein
letmein1
letmein123
open_sesame
opensesame
opensesame123
trustno1
trustnoone
adminctf
rootctf
superuser
sudo
sudoctf
challenger
challenger1
challenge
challenge1
challenge2
challenge3
challengeaccepted
ctfaccepted
iwanttheflag
gimmie_the_flag
showmetheflag
iamreverse
iamreverser
iamhacker
iam1337
1337ctf
1337flag
password_flag
password_flag1
guessme
guess_password
guesspassword
guessmypassword
check_password
checkpassword
validatepassword
wrong_password
wrongpassword
right_password
rightpassword
yesflag
noflag</details>

Unfortunately, none of my custom words were the password.

After letting it run for a few minutes on the `rockyou.txt` wordlist I realize that I might need a faster solution.

![image-20251212204015011](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212204015011.png)

If it takes roughly *174MS* per password check and `rockyou.txt` contains `~14,340,000` passwords. Then that means it will take a ***WHOPPING*** *2,495,160,000MS* = *2,495,160 seconds* = *41,586 minutes* = *693 hours*... ***OR*** a whole ***28 DAYS*** to get through just `rockyou.txt`.

I rewrite my implementation to utilize threading in order to maximize how fast I am able to hash as to deduce if brute forcing this *CTF* is even worth it.

```bash
# Process directory with 16 threads and log output to file
py bruteforce.py ./wordlists --threads 16 --log-file rockyou_results.txt
```

This has definitely helped increase the speed at which the password hashing and checking is being done at:

![image-20251212205406202](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251212205406202.png)

So at *78.3* password checks a second, this new version should take *183,198 seconds* = *3,053 minutes* = *50.9 hours*... ***OR*** about ***2.1 DAYS***. A *LOT* better than *28 days* but still not that great.

Whilst this runs on one computer, I set up another computer with roughly the same specs to tackle other word lists from [Seclist's Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords) folder. I'll report back in a few days - hopefully a lot sooner.



---

## 8. Useful Notes, Reminders, and Definitions

### 8.1 Windows x64 Calling Convention

On Windows x64 calling convention:

- RCX = 1st parameter
- RDX = 2nd
- R8  = 3rd
- R9  = 4th
- RAX = return value
- If there are *more than four arguements*, the rest go on the *stack*.



### 8.2 Function Prototypes

#### 8.2.1 USER32.DLL.RegisterClassW

```c
ATOM RegisterClassW(
    const WNDCLASSW *lpWndClass  // RCX
);
```



#### 8.2.1 USER32.DLL.CreateWindowExW

```c
HWND CreateWindowExW(
    DWORD     dwExStyle,   // RCX
    LPCWSTR   lpClassName, // RDX
    LPCWSTR   lpWindowName,// R8
    DWORD     dwStyle,     // R9
    int       x,           // [rsp+20]
    int       y,           // [rsp+28]
    int       nWidth,      // [rsp+30]
    int       nHeight,     // [rsp+38]
    HWND      hWndParent,  // [rsp+40]
    HMENU     hMenu,       // [rsp+48]
    HINSTANCE hInstance,   // [rsp+50]
    LPVOID    lpParam      // [rsp+58]
);
```



#### 8.2.3 WndProc

```c
LRESULT CALLBACK WndProc(
    HWND   hWnd,    // RCX
    UINT   uMsg,    // EDX
    WPARAM wParam,  // R8
    LPARAM lParam   // R9
);
```



#### 8.2.4 USER32.DLL.SetWindowLongPtrW

```c
LONG_PTR SetWindowLongPtrW(
    HWND   hWnd,   		// RCX
    int    nIndex, 		// RDX
    LONG_PTR dwNewLong 	// R8
);
```

**RCX** = Window handle being modified

**RDX** = `nIndex`: If this is **-4** (`GWLP_WNDPROC`), they’re changing the WndProc.

**R8** = `dwNewLong`: This is the **NEW WndProc pointer**.



---

## 9. Findings Log

Although the binary is a console executable, it doesn’t use the standard `ReadConsole`/`ReadFile` APIs. Instead, on startup it registers a custom window class and creates a (hidden) window, then enters a classic Win32 message loop (`GetMessage`/`DispatchMessage` + `PeekMessageW`). By grabbing the `lpfnWndProc` pointer during `RegisterClassW` and breakpoints in the window procedure, I observed password characters being received via `WM_CHAR` messages and pushed into an internal buffer before validation.



---

## 10. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.
