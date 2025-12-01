# crackmes.one

A collection of reverse engineering challenges and crackmes from [crackmes.one](https://crackmes.one/), organized with solutions and analysis.

## 📋 About

This repository contains a collection of crackme challenges that I've solved, along with their binaries, solutions, and write-ups. Each challenge is organized in its own directory with all necessary files and documentation.

## 📁 Repository Structure

```
crackmes.one/
├── [challenge-name]/
│   ├── binary/              # Executable and required DLLs
│   ├── flag.txt             # The solution flag
│   ├── zip-password.txt     # Password for the original challenge zip
│   ├── [challenge].zip      # Original challenge archive
│   ├── [challenge] - Solution.pdf  # Detailed solution write-up
│   └── [author]'s [challenge].url  # Shortcut link to challenge page
└── README.md
```

## 🎯 Challenges

### illusionxxx - simple crackme
- **Difficulty**: 1.5/6.0
- **Author**: illusionxxx
- **Status**: ✅ Solved
- **Solution**: See `illusionxxx - simple crackme/illusionxxx - simple crackme - Solution.pdf`
- **Description**: Used x64dbg to follow the string references and the main comparison loop, then analyzed the function that transforms user input. The crackme encodes the input with a per-byte XOR where the key is the length of the string, and compares it to the constant l?xo\r0e`. Reversing this length-based XOR yields the correct key.

### plikan - Ez Crackme
- **Difficulty**: 1.0/6.0
- **Author**: plikan
- **Status**: ✅ Solved
- **Solution**: See `plikan - Ez Crackme/plikan - Ez Crackme - Solution.pdf
- **Description**: Simple .NET console crackme. I used dnSpy to inspect Main, where the program compares Console.ReadLine() directly against a hard-coded string. The correct password is stored in plaintext, so no encoding or transformation was involved.

### vilxd - decode me
- **Difficulty**: 2.2/6.0
- **Author**: vilxd
- **Status**: ✅ Solved
- **Solution**: See `vilxd - decode me/vilxd - decode me - Solution.pdf`
- **Description**: Used x64dbg to analyze the main function, bypass a simple IsDebuggerPresent anti-debug check, and follow the calls that read, encode, and compare the user input. The program converts each character to a \xHH form using the format string "\\x%02X" and compares against a stored constant, revealing the correct password.

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

