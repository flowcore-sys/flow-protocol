@echo off
echo === Building CUDA for RTX 30/40/50 series ===
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "c:\Flow Protocol"

echo Compiling CUDA kernel for RTX 30/40/50 series...
"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\bin\nvcc.exe" ^
    -c src\miner\keccak256_cuda.cu ^
    -o build-gpu\keccak256_cuda.obj ^
    -Iinclude -Isrc ^
    -O2 --use_fast_math ^
    -gencode arch=compute_86,code=sm_86 ^
    -gencode arch=compute_89,code=sm_89 ^
    -gencode arch=compute_120,code=sm_120 ^
    -Xcompiler "/utf-8 /W0" ^
    2>&1

if %ERRORLEVEL% NEQ 0 (
    echo CUDA compile failed. Exit code: %ERRORLEVEL%
    pause
    exit /b 1
)

echo CUDA compile SUCCESS!

echo Linking...
link.exe /OUT:build-gpu\ftc-miner-gpu.exe ^
    build-gpu\gpu_miner_main.obj ^
    build-gpu\gpu_miner.obj ^
    build-gpu\keccak256_opencl.obj ^
    build-gpu\keccak256_cuda.obj ^
    build-gpu\Release\ftc-core.lib ^
    "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\lib\x64\cudart.lib" ^
    ws2_32.lib bcrypt.lib

if %ERRORLEVEL% NEQ 0 (
    echo Link failed. Exit code: %ERRORLEVEL%
    pause
    exit /b 1
)

echo === BUILD SUCCESS ===
dir build-gpu\ftc-miner-gpu.exe
