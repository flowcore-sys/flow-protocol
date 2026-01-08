@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "c:\Flow Protocol"

echo Compiling CUDA kernel (multi-GPU support)...
REM Generate code for supported GPU architectures:
REM sm_75=Turing(RTX2000), sm_86=Ampere(RTX3000), sm_89=Ada(RTX4000), sm_100=Blackwell DC, sm_120=RTX5090
nvcc -c -O3 -use_fast_math -gencode=arch=compute_75,code=sm_75 -gencode=arch=compute_86,code=sm_86 -gencode=arch=compute_89,code=sm_89 -gencode=arch=compute_100,code=sm_100 -gencode=arch=compute_120,code=sm_120 -gencode=arch=compute_120,code=compute_120 -I include -I src -o build-gpu/keccak256_cuda.obj src/miner/keccak256_cuda.cu
if errorlevel 1 goto error

echo Compiling gpu_miner.c...
cl /c /O2 /DFTC_HAS_CUDA /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /I include /I src /Fo:build-gpu/gpu_miner.obj src/miner/gpu_miner.c
if errorlevel 1 goto error

echo Compiling keccak256_opencl.c (stubs)...
cl /c /O2 /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /I include /I src /Fo:build-gpu/keccak256_opencl.obj src/miner/keccak256_opencl.c
if errorlevel 1 goto error

echo Compiling gpu_miner_main.c...
cl /c /O2 /DFTC_HAS_CUDA /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /I include /I src /Fo:build-gpu/gpu_miner_main.obj node/gpu_miner_main.c
if errorlevel 1 goto error

echo Linking ftc-miner-gpu.exe...
link /OUT:release/ftc-miner-gpu.exe /LIBPATH:"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\lib\x64" build-gpu/gpu_miner.obj build-gpu/gpu_miner_main.obj build-gpu/keccak256_cuda.obj build-gpu/keccak256_opencl.obj build-gpu/Release/ftc-core.lib cudart.lib ws2_32.lib
if errorlevel 1 goto error

echo Build successful!
goto end

:error
echo Build failed!
exit /b 1

:end
