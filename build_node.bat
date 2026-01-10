@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set SRC_DIR=c:\Flow Protocol
set BUILD_DIR=c:\ftcbuild\node

rd /s /q "%BUILD_DIR%" 2>nul
mkdir "%BUILD_DIR%"

echo.
echo === Compiling FTC Node ===
cd /d "%BUILD_DIR%"
cl /c /O2 /I"%SRC_DIR%\include" /I"%SRC_DIR%\src" /DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
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
    "%SRC_DIR%\src\stratum\stratum.c" ^
    "%SRC_DIR%\src\p2pool\p2pool.c" ^
    "%SRC_DIR%\src\p2p\p2p.c" ^
    "%SRC_DIR%\node\full_node.c" ^
    "%SRC_DIR%\node\main.c"
if errorlevel 1 goto error

echo.
echo === Linking ===
link /OUT:ftc-node.exe *.obj ws2_32.lib advapi32.lib
if errorlevel 1 goto error

echo.
echo === SUCCESS ===
copy ftc-node.exe "%SRC_DIR%\release\" /Y
echo Built: %BUILD_DIR%\ftc-node.exe
goto end

:error
echo.
echo === BUILD FAILED ===

:end
