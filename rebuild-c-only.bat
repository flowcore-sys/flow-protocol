@echo off
echo === Rebuilding C files only ===
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "c:\Flow Protocol"

set CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1

echo Compiling C files...
cl.exe /O2 /MD /c /utf-8 /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /Iinclude /Isrc /I"%CUDA_PATH%\include" src\miner\gpu_miner.c /Fobuild-gpu\gpu_miner.obj
if errorlevel 1 goto :error

cl.exe /O2 /MD /c /utf-8 /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /Iinclude /Isrc /I"%CUDA_PATH%\include" src\miner\keccak256_opencl.c /Fobuild-gpu\keccak256_opencl.obj
if errorlevel 1 goto :error

cl.exe /O2 /MD /c /utf-8 /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA /Iinclude /Isrc /I"%CUDA_PATH%\include" node\gpu_miner_main.c /Fobuild-gpu\gpu_miner_main.obj
if errorlevel 1 goto :error

echo Linking...
link.exe /OUT:build-gpu\ftc-miner-gpu.exe ^
    build-gpu\gpu_miner_main.obj ^
    build-gpu\gpu_miner.obj ^
    build-gpu\keccak256_opencl.obj ^
    build-gpu\keccak256_cuda.obj ^
    build-gpu\Release\ftc-core.lib ^
    "%CUDA_PATH%\lib\x64\cudart.lib" ^
    ws2_32.lib bcrypt.lib
if errorlevel 1 goto :error

echo === BUILD SUCCESS ===
dir build-gpu\ftc-miner-gpu.exe
goto :end

:error
echo Build failed!
exit /b 1

:end
