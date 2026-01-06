# FTC GPU Miner Rebuild Script (C files only)
# Reuses existing CUDA kernel, recompiles C files
# Run from Developer PowerShell for VS 2022

$ErrorActionPreference = "Stop"

Write-Host "=== FTC GPU Miner Rebuild (C only) ===" -ForegroundColor Cyan

# Paths
$SRC = $PSScriptRoot
$BUILD = Join-Path $SRC "build-gpu"
$CUDA_PATH = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
$CUDA_INCLUDE = Join-Path $CUDA_PATH "include"
$CUDART = Join-Path $CUDA_PATH "lib\x64\cudart.lib"

# Check for existing CUDA kernel
$cudaObj = Join-Path $BUILD "keccak256_cuda.obj"
if (-not (Test-Path $cudaObj)) {
    Write-Host "ERROR: CUDA kernel not found at $cudaObj" -ForegroundColor Red
    Write-Host "Run build-gpu-manual.ps1 first to compile CUDA kernel" -ForegroundColor Yellow
    exit 1
}

# Step 1: Rebuild core library
Write-Host "`n[1/3] Rebuilding core library..." -ForegroundColor Yellow
Push-Location $BUILD
& cmake --build . --config Release --target ftc-core
Pop-Location

# Step 2: Compile GPU miner C files
Write-Host "`n[2/3] Compiling GPU miner C files..." -ForegroundColor Yellow

$clArgs = @(
    "/O2", "/MD", "/c", "/utf-8",
    "/DFTC_WINDOWS", "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX", "/DFTC_HAS_CUDA",
    "/I$SRC\include", "/I$SRC\src", "/I$CUDA_INCLUDE"
)

& cl.exe @clArgs "$SRC\src\miner\gpu_miner.c" "/Fo$BUILD\gpu_miner.obj"
if ($LASTEXITCODE -ne 0) { Write-Host "gpu_miner.c compile failed"; exit 1 }

& cl.exe @clArgs "$SRC\src\miner\keccak256_opencl.c" "/Fo$BUILD\keccak256_opencl.obj"
if ($LASTEXITCODE -ne 0) { Write-Host "keccak256_opencl.c compile failed"; exit 1 }

& cl.exe @clArgs "$SRC\node\gpu_miner_main.c" "/Fo$BUILD\gpu_miner_main.obj"
if ($LASTEXITCODE -ne 0) { Write-Host "gpu_miner_main.c compile failed"; exit 1 }

# Step 3: Link everything
Write-Host "`n[3/3] Linking ftc-miner-gpu.exe..." -ForegroundColor Yellow
& link.exe "/OUT:$BUILD\ftc-miner-gpu.exe" `
    "$BUILD\gpu_miner_main.obj" `
    "$BUILD\gpu_miner.obj" `
    "$BUILD\keccak256_opencl.obj" `
    "$BUILD\keccak256_cuda.obj" `
    "$BUILD\Release\ftc-core.lib" `
    "$CUDART" `
    ws2_32.lib `
    bcrypt.lib

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== Build Complete ===" -ForegroundColor Green
    Write-Host "GPU miner: $BUILD\ftc-miner-gpu.exe" -ForegroundColor Cyan
} else {
    Write-Host "Link failed" -ForegroundColor Red
    exit 1
}
