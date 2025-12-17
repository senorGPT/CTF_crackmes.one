# Building the Keygen Executable

This guide explains how to package the keygen into a standalone executable.

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Option 1: Using the Build Script (Windows)

Simply run:
```bash
build.bat
```

## Option 2: Manual Build

### Step 1: Install PyInstaller

**Using Python Launcher (Windows, recommended):**
```bash
py -m pip install pyinstaller
```

**Using traditional Python command:**
```bash
pip install pyinstaller
# or
python -m pip install pyinstaller
```

### Step 2: Build the Executable

**For a single-file executable (recommended):**

**Using Python Launcher (Windows):**
```bash
py -m PyInstaller --onefile --name keygen --console keygen.py
```

**Using traditional Python command:**
```bash
pyinstaller --onefile --name keygen --console keygen.py
# or
python -m PyInstaller --onefile --name keygen --console keygen.py
```

**For a one-folder distribution (faster startup, easier debugging):**

**Using Python Launcher (Windows):**
```bash
py -m PyInstaller --name keygen --console keygen.py
```

**Using traditional Python command:**
```bash
pyinstaller --name keygen --console keygen.py
# or
python -m PyInstaller --name keygen --console keygen.py
```

### Step 3: Find Your Executable

After building, the executable will be in the `dist` folder:
- **Windows**: `dist\keygen.exe`
- **Linux/Mac**: `dist/keygen`

## Changing the Executable Name

To change the name of the executable, modify the `--name` parameter in the build command:

**In `build.bat`:**
```batch
py -m PyInstaller --onefile --name YOUR_NAME --console keygen.py
```

**Example:** To create an executable named "KeyGenMeV3":
```batch
py -m PyInstaller --onefile --name KeyGenMeV3 --console keygen.py
```

This will create:
- **Windows**: `dist\KeyGenMeV3.exe`
- **Linux/Mac**: `dist/KeyGenMeV3`

## Build Options Explained

- `--onefile`: Creates a single executable file (larger but easier to distribute)
- `--name keygen`: Names the executable "keygen" (or "keygen.exe" on Windows) - **change this to customize the name**
- `--console`: Keeps the console window (for command-line interface)
- `--noconsole`: Hides the console (use if you add a GUI later)

## Advanced: Custom Build Configuration

For more control, you can create a `.spec` file:

**Using Python Launcher (Windows):**
```bash
py -m PyInstaller --name keygen keygen.py
```

**Using traditional Python command:**
```bash
pyinstaller --name keygen keygen.py
# or
python -m PyInstaller --name keygen keygen.py
```

This creates `keygen.spec` which you can edit, then rebuild with:

**Using Python Launcher (Windows):**
```bash
py -m PyInstaller keygen.spec
```

**Using traditional Python command:**
```bash
pyinstaller keygen.spec
# or
python -m PyInstaller keygen.spec
```

## Distribution

The executable in the `dist` folder is standalone and can be distributed without Python installed. Just copy the `.exe` file (Windows) or the executable (Linux/Mac) to any machine.

## Troubleshooting

- **Large file size**: This is normal for PyInstaller executables (includes Python runtime)
- **Antivirus warnings**: Some antivirus software may flag PyInstaller executables as suspicious (false positive)
- **Import errors**: If you add external dependencies, make sure they're installed before building

