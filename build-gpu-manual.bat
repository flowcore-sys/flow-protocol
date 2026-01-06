@echo off
setlocal enabledelayedexpansion

echo === FTC GPU Miner Build ===
echo.

set SRC=%~dp0
set SRC=%SRC:~0,-1%
set BUILD=%SRC%\build-gpu
set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"

:: Check for CUDA
if not exist "%CUDA_PATH%\bin\nvcc.exe" (
    echo ERROR: CUDA not found at %CUDA_PATH%
    exit /b 1
)

:: Create build directory
if not exist "%BUILD%" mkdir "%BUILD%"

:: Step 1: Build core library
echo [1/4] Building core library...
cd /d "%BUILD%"
cmake -G "Visual Studio 17 2022" -A x64 -DFTC_BUILD_CUDA=OFF "%SRC%"
if errorlevel 1 goto :error
cmake --build . --config Release --target ftc-core
if errorlevel 1 goto :error

:: Step 2: Compile CUDA kernel (RTX 30/40/50 series support)
echo.
echo [2/4] Compiling CUDA kernel for RTX 30/40/50 series...
"%CUDA_PATH%\bin\nvcc.exe" -c "%SRC%\src\miner\keccak256_cuda.cu" -I"%SRC%\include" -I"%SRC%\src" -o "%BUILD%\keccak256_cuda.obj" ^
    --generate-code=arch=compute_86,code=sm_86 ^
    --generate-code=arch=compute_89,code=sm_89 ^
    --generate-code=arch=compute_120,code=sm_120 ^
    -O2 --use_fast_math -Xcompiler "/utf-8 /W0"
if errorlevel 1 goto :error

:: Step 3: Compile C files
echo.
echo [3/4] Compiling GPU miner...
cl.exe /O2 /MD /c /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /I"%SRC%\include" /I"%SRC%\src" /I"%CUDA_PATH%\include" "%SRC%\src\miner\gpu_miner.c" /Fo"%BUILD%\gpu_miner.obj"
if errorlevel 1 goto :error
cl.exe /O2 /MD /c /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /I"%SRC%\include" /I"%SRC%\src" /I"%CUDA_PATH%\include" "%SRC%\src\miner\keccak256_opencl.c" /Fo"%BUILD%\keccak256_opencl.obj"
if errorlevel 1 goto :error
cl.exe /O2 /MD /c /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /I"%SRC%\include" /I"%SRC%\src" /I"%CUDA_PATH%\include" "%SRC%\node\gpu_miner_main.c" /Fo"%BUILD%\gpu_miner_main.obj"
if errorlevel 1 goto :error

:: Step 4: Link
echo.
echo [4/4] Linking ftc-miner-gpu.exe...
link.exe /OUT:"%BUILD%\ftc-miner-gpu.exe" "%BUILD%\gpu_miner_main.obj" "%BUILD%\gpu_miner.obj" "%BUILD%\keccak256_opencl.obj" "%BUILD%\keccak256_cuda.obj" "%BUILD%\Release\ftc-core.lib" "%CUDA_PATH%\lib\x64\cudart.lib" ws2_32.lib bcrypt.lib
if errorlevel 1 goto :error

echo.
echo === Build Complete ===
echo GPU miner: %BUILD%\ftc-miner-gpu.exe
goto :end

:error
echo.
echo Build failed!
exit /b 1

:end
endlocal
