## crack the points — `solution/` helpers

This folder contains the **trainer scripts** and a small reusable helper package used to patch the crackme at runtime.

### Files

- **`trainer.py`**: The “main” trainer. Supports CLI flags (e.g. `--edx`, `--quiet`) and prints the target’s output.
- **`simple_trainer.py`**: A smaller/minimal version used during development/debugging.
- **`trainerlib/`**: Portable helper package (Windows-only) for trainer development:
  - **`winapi.py`**: WinAPI wrappers (CreateProcessW suspended, RPM/WPM, VirtualAllocEx code cave allocation, etc.)
  - **`asm.py`**: Small instruction encoders (`jmp rel32`, `call rel32`, `call [rip+disp32]`)
  - **`bits.py`**: Misc helpers (e.g. `print_hex`)

### Usage

Run the main trainer from this directory:

```bash
py ./trainer.py --edx 1337
```

Quiet mode (only show the program output / essential errors):

```bash
py ./trainer.py --edx 1337 --quiet
```

If you need to point at a different binary path:

```bash
py ./trainer.py --exe "..\binary\point-cracker.exe" --edx 99
```

### Notes

- The trainer uses a **trampoline + allocated code cave** (`VirtualAllocEx`) to avoid overwriting “maybe not free” bytes inside the module.
- `--edx` is encoded with `mov edx, imm32`, so the value is a **32-bit immediate**; `%d` will print it as a **signed 32-bit** integer.


