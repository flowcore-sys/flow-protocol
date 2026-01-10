@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8
set SRC_DIR=c:\Flow Protocol
set BUILD_DIR=c:\ftcbuild\miner

rd /s /q "%BUILD_DIR%" 2>nul
mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

echo.
echo === Compiling CUDA kernel ===
"%CUDA_PATH%\bin\nvcc" -c "%SRC_DIR%\src\miner\keccak256_cuda.cu" -o keccak256_cuda.obj ^
    -I"%SRC_DIR%\include" -I"%SRC_DIR%\src" ^
    -gencode=arch=compute_75,code=sm_75 ^
    -gencode=arch=compute_86,code=sm_86 ^
    -gencode=arch=compute_89,code=sm_89 ^
    -gencode=arch=compute_100,code=sm_100 ^
    -gencode=arch=compute_120,code=sm_120 ^
    -gencode=arch=compute_120,code=compute_120 ^
    -O3 -DFTC_HAS_CUDA
if errorlevel 1 goto error

echo.
echo === Compiling C files ===
cl /c /O2 /I"%SRC_DIR%\include" /I"%SRC_DIR%\src" /I"%CUDA_PATH%\include" ^
    /DFTC_HAS_CUDA /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
    "%SRC_DIR%\src\crypto\keccak256.c" ^
    "%SRC_DIR%\src\crypto\tweetnacl.c" ^
    "%SRC_DIR%\src\crypto\ed25519.c" ^
    "%SRC_DIR%\src\crypto\keys.c" ^
    "%SRC_DIR%\src\crypto\merkle.c" ^
    "%SRC_DIR%\src\core\block.c" ^
    "%SRC_DIR%\src\core\tx.c" ^
    "%SRC_DIR%\src\core\utxo.c" ^
    "%SRC_DIR%\src\core\consensus.c" ^
    "%SRC_DIR%\src\core\mempool.c" ^
    "%SRC_DIR%\src\rpc\rpc.c" ^
    "%SRC_DIR%\src\wallet\wallet.c" ^
    "%SRC_DIR%\src\miner\miner.c" ^
    "%SRC_DIR%\src\miner\gpu_miner.c" ^
    "%SRC_DIR%\node\gpu_miner_main.c"
if errorlevel 1 goto error

echo.
echo === Linking ===
link /OUT:ftc-miner-gpu.exe *.obj ^
    "%CUDA_PATH%\lib\x64\cudart_static.lib" ^
    ws2_32.lib advapi32.lib
if errorlevel 1 goto error

echo.
echo === SUCCESS ===
copy ftc-miner-gpu.exe "%SRC_DIR%\release\" /Y
echo Built: %BUILD_DIR%\ftc-miner-gpu.exe
goto end

:error
echo.
echo === BUILD FAILED ===

:end
