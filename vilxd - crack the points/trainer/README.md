# `trainer.py` — point-cracker patcher (Windows)

This script patches instructions inside **`point-cracker.exe`** either:

- **in a running process** (by PID or process name), or
- by **launching the EXE suspended**, patching while it’s paused, then resuming.

It computes the patch address as:

\[
\text{patch\_va} = \text{module\_base} + \text{RVA}
\]

## Requirements

- Windows
- Python 3.10+ (any recent Python should work)
- Enough rights to open/patch the target process (you may need to run the terminal as Admin)

## Quick start (common commands)

### 1) Launch suspended, patch, resume (recommended)

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --exe "vilxd - crack the points/binary/point-cracker.exe" `
  --rva 0x1193C `
  --bytes "B8 39 05 00 00 90"
```

### 2) Launch suspended, patch EDX to a user value, resume

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --exe "vilxd - crack the points/binary/point-cracker.exe" `
  --rva 0x1193C `
  --edx 1337
```

### 3) Dry run (show old/new bytes, do not write)

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --exe "vilxd - crack the points/binary/point-cracker.exe" `
  --rva 0x1193C `
  --edx 1337 `
  --dry-run
```

### 4) Patch an already running process (by process name)

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --process "point-cracker.exe" `
  --rva 0x1193C `
  --edx 1337
```

### 5) Patch an already running process (by PID)

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --pid 1234 `
  --module "point-cracker.exe" `
  --rva 0x1193C `
  --edx 1337
```

## Options

### Target selection (choose one mode)

- **`--exe <path>`**: Launch the EXE in a **suspended** state, patch it, then resume (unless `--no-resume`).
- **`--pid <pid>`**: Patch an already running process by PID.
- **`--process <name>`**: Patch an already running process by executable name (default: `point-cracker.exe`).

> Note: use **either** `--exe` **or** `--pid/--process` (not both).

### Process launch options (only with `--exe`)

- **`--exe-args -- <args...>`**: Arguments passed to the launched EXE. Everything after `--exe-args` is forwarded.

Example:

```powershell
python "vilxd - crack the points/trainer/trainer.py" `
  --exe "vilxd - crack the points/binary/point-cracker.exe" `
  --exe-args -- --some-flag 123 `
  --rva 0x1193C `
  --edx 1337
```

- **`--no-resume`**: Keep the main thread suspended after patching (useful if you want to attach a debugger first).

### Patch location

- **`--module <name>`**: Module whose base address will be used for `base + RVA` (default: `point-cracker.exe`).
  - In `--exe` mode, if you don’t override `--module`, the script will patch the launched EXE module.
- **`--rva <int>`**: RVA to patch (supports `0x...` hex). Default: `0x1193C`.

### Patch content (choose one)

- **`--edx <int>`**: Build patch bytes as `mov edx, imm32`.
  - Opcode: `BA <imm32 little-endian>`
  - Overrides `--bytes`.
- **`--bytes "<hex bytes>"`**: Space-separated hex bytes to write.
  - Example: `"B8 39 05 00 00 90"`

### Safety

- **`--dry-run`**: Reads and prints the current bytes at the patch site and shows what would be written, but does not write.

## Important note: `xor edx, edx` → `mov edx, imm32`

`xor edx, edx` is **2 bytes** (`31 D2`), but `mov edx, imm32` is **5 bytes** (`BA xx xx xx xx`).

That means you can’t safely replace a standalone `xor edx, edx` unless you ensure you are overwriting **at least 5 bytes** of instructions at that address (often by patching additional bytes after it, padding with NOPs, or using a trampoline/code cave).

If you paste the bytes around the target instruction (next ~10–15 bytes), it’s easy to confirm whether a 5-byte overwrite is safe at that location.


