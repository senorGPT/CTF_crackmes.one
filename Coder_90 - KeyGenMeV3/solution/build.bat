@echo off
REM Build script for creating executable with PyInstaller

echo Installing PyInstaller...
py -m pip install pyinstaller

echo.
echo Building executable...
py -m PyInstaller --onefile --name "KeyGenMeV3 - keygen" --console keygen.py

echo.
echo Build complete! Executable is in the 'dist' folder.
pause

