# crackmes.one

A collection of reverse engineering challenges and crackmes from [crackmes.one](https://crackmes.one/), organized with solutions and analysis.

## 📋 About

This repository contains a collection of crackme challenges that I've solved, along with their binaries, solutions, and write-ups. Each challenge is organized in its own directory with all necessary files and documentation.

## 📁 Repository Structure

```
crackmes.one/
├── [challenge-name]/            # One folder per crackme
│   ├── binary/                  # Executable and required DLLs
│   ├── flag.txt                 # The solution flag (if applicable)
│   ├── zip-password.txt         # Password for the original crackmes.one zip
│   ├── [id].zip                 # Original crackme archive (crackmes.one id)
│   ├── cover.png                # Challenge cover (when available)
│   ├── [challenge] - Solution.pdf|md  # Solution write-up
│   ├── [author]'s [challenge].url     # Shortcut link to crackmes.one page
│   ├── patched/                 # Patched binaries (when applicable)
│   └── solution/                # Scripts/tools (keygen, bruteforce, trainer, etc.)
```

## 🎯 Challenges

<details>
<summary><b>plikan - Ez Crackme</b> | Difficulty: 1.0/6.0</summary>

- **Difficulty**: 1.0/6.0
- **Author**: plikan
- **Status**: ✅ Solved
- **Solution**: See `plikan - Ez Crackme/plikan - Ez Crackme - Solution.pdf`
- **Description**: Simple .NET console crackme. I used dnSpy to inspect Main, where the program compares Console.ReadLine() directly against a hard-coded string. The correct password is stored in plaintext, so no encoding or transformation was involved.
- **Date Solved**: 2025-11-30

</details>

<details>
<summary><b>zsombii - Easy crackme</b> | Difficulty: 1.0/6.0</summary>

- **Difficulty**: 1.0/6.0
- **Author**: zsombii
- **Status**: ✅ Solved
- **Solution**: See `zsombii - Easy crackme/zsombii - Easy crackme - Solution.pdf`
- **Description**: Java `.jar` crackme. Using JADX, I recovered `checkValidity()` which scores the 10-character key by counting how many characters satisfy `(ch & 3) == 0` (i.e., ASCII divisible by 4). A key is valid if the score is exactly 4. I also wrote a small Python keygen in `zsombii - Easy crackme/solution/` to generate valid keys.
- **Date Solved**: 2025-12-17

</details>

<details>
<summary><b>NullerF - Easiest</b> | Difficulty: 1.1/6.0</summary>

- **Difficulty**: 1.1/6.0
- **Author**: NullerF
- **Status**: ✅ Solved
- **Solution**: See `NullerF - Easiest/NullerF - Easiest - Solution.pdf`
- **Description**: Windows x86-64 crackme. Traced string references (e.g., `"Enter PIN:"`) in x64dbg back into `main`, identified the numeric PIN check, and patched/bypassed the failure path to reach the success branch and recover the correct input - 8569.
- **Date Solved**: 2025-12-19

</details>

<details>
<summary><b>illusionxxx - simple crackme</b> | Difficulty: 1.5/6.0</summary>

- **Difficulty**: 1.5/6.0
- **Author**: illusionxxx
- **Status**: ✅ Solved
- **Solution**: See `illusionxxx - simple crackme/illusionxxx - simple crackme - Solution.pdf`
- **Description**: Used x64dbg to follow the string references and the main comparison loop, then analyzed the function that transforms user input. The crackme encodes the input with a per-byte XOR where the key is the length of the string, and compares it to the constant l?xo\r0e`. Reversing this length-based XOR yields the correct key.
- **Date Solved**: 2025-11-29

</details>

<details>
<summary><b>vilxd - crack the points</b> | Difficulty: 2.0/6.0</summary>

- **Difficulty**: 2.0/6.0
- **Author**: vilxd
- **Status**: ✅ Solved
- **Solution**: See `vilxd - crack the points/vilxd - crack the points - Solution.md`
- **Description**: Patch/trainer-style challenge: the program prints `Your count points is %d` with a hard-coded zeroed value. I located the call site in x64dbg/Ghidra and wrote a Python trainer that launches the process suspended, computes `moduleBase + RVA`, and patches the code to load a user-chosen value into `EDX` before the `printf` call. To make the patch robust, I used a trampoline and an allocated code cave (`VirtualAllocEx`) instead of guessing free space in `.text`.
- **Date Solved**: 2025-12-17

</details>

<details>
<summary><b>FentCat - Assembler Crackme</b> | Difficulty: 2.0/6.0</summary>

- **Difficulty**: 2.0/6.0
- **Author**: FentCat
- **Status**: ✅ Solved
- **Solution**: See `FentCat - Assembler Crackme/FentCat - Assembler Crackme - Solution.md`
- **Description**: x86 assembler crackme. Traced the password path from `ReadConsoleA` into the validation routine and identified an 8-byte memcmp-style loop against a static byte table. The correct password is the exact 8-byte sequence `@CBEDGFI`.
- **Date Solved**: 2025-12-20

</details>

<details>
<summary><b>sally1337 - StaticAuth</b> | Difficulty: 2.0/6.0</summary>

- **Difficulty**: 2.0/6.0
- **Author**: sally1337
- **Status**: ✅ Solved
- **Solution**: See `sally1337 - StaticAuth/sally1337 - StaticAuth - Solution.md`
- **Description**: Windows x86-64 “authentication code” crackme solved via static analysis (Binary Ninja HLIL). Recovered the runtime-reconstructed password from lightly obfuscated embedded data; correct code is `goodjob123`.
- **Date Solved**: 2025-12-24

</details>

<details>
<summary><b>vilxd - decode me</b> | Difficulty: 2.2/6.0</summary>

- **Difficulty**: 2.2/6.0
- **Author**: vilxd
- **Status**: ✅ Solved
- **Solution**: See `vilxd - decode me/vilxd - decode me - Solution.pdf`
- **Description**: Used x64dbg to analyze the main function, bypass a simple IsDebuggerPresent anti-debug check, and follow the calls that read, encode, and compare the user input. The program converts each character to a \xHH form using the format string "\\x%02X" and compares against a stored constant, revealing the correct password.
- **Date Solved**: 2025-12-01

</details>

<details>
<summary><b>Biglsim04 - puzzle</b> | Difficulty: 2.5/6.0</summary>

- **Difficulty**: 2.5/6.0
- **Author**: Biglsim04
- **Status**: ✅ Solved
- **Solution**: See `Biglsim04 - puzzle/Biglsim04 - puzzle - Solution.pdf`
- **Description**: Command-line crackme that hides both its console strings and password check behind a simple XOR-0x9F encoding layer. Using CFF Explorer and Detect It Easy (DIE) for static recon plus x64dbg breakpoints on WriteFile/ReadFile, I traced the input path to a 9-character length check and a character-by-character comparison against an XOR-decoded constant. By NOP-ing the failure branch and single-stepping the comparison loop, I recovered the cleartext password MYPASS123 and confirmed the same XOR-0x9F scheme is used to decode the “Hello World!”, “Enter password:” and “Access Granted/Denied!” strings at runtime.
- **Date Solved**: 2025-12-11

</details>

<details>
<summary><b>Coder_90 - KeyGenMeV3</b> | Difficulty: 3.0/6.0</summary>

- **Difficulty**: 3.0/6.0
- **Author**: Coder_90
- **Status**: ✅ Solved
- **Solution**: See `Coder_90 - KeyGenMeV3/Coder_90 - KeyGenMeV3 - Solution.pdf`
- **Description**: My first keygen; Win32 GUI crackme with Name + Key validation. Used CFF Explorer for static analysis and x64dbg for dynamic analysis to trace the key validation algorithm. The program processes the name input through a semi-complex encoding function that uses different mixing operations for even/odd characters, involving ROL operations, XOR, and addition with constants. Reversed the algorithm and implemented a Python keygen that generates valid keys for any given name.
- **Date Solved**: 2025-12-07

</details>

<details>
<summary><b>RodrigoTeixeira - Roullete Simulator</b> | Difficulty: 3.0/6.0</summary>

- **Difficulty**: 3.0/6.0
- **Author**: RodrigoTeixeira
- **Status**: ✅ Solved
- **Solution**: See `RodrigoTeixeira - Roullete Simulator/RodrigoTeixeira - Roullete Simulator - Solution.md`
- **Description**: Java roulette simulator. Decompiled with JADX and recovered a custom 16-bit PRNG used for win/loss. Brute-forced the PRNG seed from observed outcomes to predict future rounds, then used a betting strategy to grow balance until a 32-bit signed integer overflow flips it negative, satisfying the “win” condition.
- **Date Solved**: 2025-12-20

</details>

<details>
<summary><b>NemesisX - GuessPassword</b> | Difficulty: 3.5/6.0</summary>

- **Difficulty**: 3.5/6.0
- **Author**: NemesisX
- **Status**: 🔍 Analyzed
- **Solution**: See `NemesisX - GuessPassword/NemesisX - GuessPassword - Solution.md`
- **Description**: Python-based crackme packaged with PyInstaller. Used x64dbg for initial analysis and identified it as a Python executable. Extracted the Python bytecode using pyinstxtractor, then decompiled the `.pyc` file using decompyle3 to recover the source code. The program uses bcrypt (cost factor 12) to hash and validate passwords, storing the hash `$2b$12$pBRbErJA/R.oPinWBAx4buejz59JCDiARNr07zSRrK/1F8jHpMzSm`. Since bcrypt is a one-way hash, implemented a multi-threaded Python bruteforce script with timing, logging, and resume capabilities to attempt password recovery from wordlists. Reverse engineering complete; solution method implemented and running, awaiting brute force completion (limited by computational resources).
- **Date Analyzed**: 2025-12-12

</details>

## 🚀 Getting Started

1. Navigate to a challenge directory
2. Extract or use the provided binary files
3. Read the solution PDF for detailed analysis
4. Try solving it yourself before checking the solution!

## 📝 Notes

- All challenges are from [crackmes.one](https://crackmes.one/)
- Solutions are provided for educational purposes
- Try to solve challenges yourself before looking at solutions
- Some challenges may require specific tools or environments

## 🛠️ Tools Used

Common tools for solving these challenges:
- **Analysis**: Detect It Easy (DiE)
- **Debuggers**: x64dbg, x32dbg
- **Disassemblers & Decompilers**: IDA Free, Ghidra
- **Dynamic Analysis**: ProcessHacker, Process Monitor, API Monitor

## 📚 Resources

- [crackmes.one](https://crackmes.one/) - Source of challenges

## ⚠️ Disclaimer

This repository is for educational purposes only. The challenges contained herein are intended to help individuals learn reverse engineering and security analysis in a legal and ethical manner.

## 📄 License

This repository contains challenges and solutions for educational purposes. Please respect the original authors' terms and conditions for each challenge. As well as crackmes.one terms and conditions as well as rules.

---

**Happy Reversing! 🔓**

