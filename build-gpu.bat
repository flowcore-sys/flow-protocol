@echo off
REM FTC GPU Miner Build Script
REM
REM Note: CUDA has issues with paths containing spaces.
REM If you encounter build errors, copy this project to a path without spaces
REM (e.g., C:\ftc-protocol) and run this script from there.

echo === FTC GPU Miner Build ===
echo.

REM Check for CUDA
where nvcc >nul 2>&1
if errorlevel 1 (
    echo ERROR: CUDA not found. Please install CUDA Toolkit.
    echo Download from: https://developer.nvidia.com/cuda-downloads
    exit /b 1
)

REM Check for Visual Studio
where cl >nul 2>&1
if errorlevel 1 (
    echo WARNING: Visual Studio not in PATH.
    echo Please run this from Developer Command Prompt for VS 2022
)

REM Create build directory
if not exist "build-gpu" mkdir build-gpu
cd build-gpu

REM Configure with CUDA support
echo Configuring CMake with CUDA support...
cmake -G "Visual Studio 17 2022" -A x64 -DFTC_BUILD_CUDA=ON ..
if errorlevel 1 (
    echo CMake configuration failed.
    exit /b 1
)

REM Build
echo.
echo Building GPU miner...
cmake --build . --config Release --target ftc-miner-gpu
if errorlevel 1 (
    echo Build failed.
    echo.
    echo If you see nvcc errors about input files, try:
    echo   1. Copy project to a path without spaces (e.g., C:\ftc-protocol)
    echo   2. Run this script from there
    exit /b 1
)

echo.
echo === Build Complete ===
echo GPU miner: build-gpu\Release\ftc-miner-gpu.exe
echo.
