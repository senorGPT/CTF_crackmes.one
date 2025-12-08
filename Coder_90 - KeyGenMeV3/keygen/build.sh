#!/bin/bash
# Build script for creating executable with PyInstaller (Linux/Mac)

echo "Installing PyInstaller..."
pip install pyinstaller

echo ""
echo "Building executable..."
pyinstaller --onefile --name keygen --console keygen.py

echo ""
echo "Build complete! Executable is in the 'dist' folder."

