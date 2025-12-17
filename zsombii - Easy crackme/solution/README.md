## zsombii - Easy crackme — Keygen

This folder contains a small Python key generator for the crackme.

### How it works (high level)

The crackme’s key check (mirrored by `is_valid()` in `keygen.py`) counts characters where:

- `(ord(ch) & 3) == 0`

A key is considered valid if exactly **4** characters satisfy that condition (`KEY_TOTAL_VALUE = 4`).

The generator builds keys by:

- picking **4 “good”** characters (that satisfy the condition)
- picking the remaining characters as **“bad”** (do not satisfy the condition)
- shuffling the result

### Requirements

- Python 3

### Usage

Run from this directory:

```bash
py ./keygen.py
```

Generate multiple keys:

```bash
py ./keygen.py --count 10
```

### CLI arguments

- **`-n, --count`**: number of keys to generate (default: `1`)
- **`--out`**: write generated keys to this file when generating multiple keys (default: `keys.txt`)
- **Key length**: always `10` characters

### Saving keys to a file

When generating multiple keys, the script prints them and also writes them to a file.

- Default file (when `--count > 1`): `keys.txt`
- Custom file: pass `--out`

```bash
py ./keygen.py --count 25 --out generated_keys.txt
```


