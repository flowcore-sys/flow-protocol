@echo off
set PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8\bin;%PATH%
set CUDACXX=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8\bin\nvcc.exe
set CUDAToolkit_ROOT=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8

cd /d "c:\Flow Protocol"
rd /s /q build 2>nul
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -DFTC_BUILD_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES="75;86;89;100;120"
cmake --build . --target ftc-miner-gpu --config Release
