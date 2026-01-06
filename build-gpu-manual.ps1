# FTC GPU Miner Build Script (PowerShell)
# Run from Developer PowerShell for VS 2022

$ErrorActionPreference = "Stop"

Write-Host "=== FTC GPU Miner Build ===" -ForegroundColor Cyan

# Paths
$SRC = $PSScriptRoot
$BUILD = Join-Path $SRC "build-gpu"
$CUDA_PATH = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
$NVCC = Join-Path $CUDA_PATH "bin\nvcc.exe"
$CUDART = Join-Path $CUDA_PATH "lib\x64\cudart.lib"

# Check for CUDA
if (-not (Test-Path $NVCC)) {
    Write-Host "ERROR: CUDA not found at $CUDA_PATH" -ForegroundColor Red
    exit 1
}

# Create build directory
New-Item -ItemType Directory -Force -Path $BUILD | Out-Null

# Step 1: Build core library with CMake (without CUDA)
Write-Host "`n[1/4] Building core library..." -ForegroundColor Yellow
Push-Location $BUILD
& cmake -G "Visual Studio 17 2022" -A x64 -DFTC_BUILD_CUDA=OFF $SRC
& cmake --build . --config Release --target ftc-core
Pop-Location

# Step 2: Compile CUDA kernel (RTX 30/40/50 series support)
Write-Host "`n[2/4] Compiling CUDA kernel for RTX 30/40/50 series..." -ForegroundColor Yellow
$CUDA_INCLUDE = Join-Path $CUDA_PATH "include"
& "$NVCC" -c "$SRC\src\miner\keccak256_cuda.cu" `
    "-I$SRC\include" `
    "-I$SRC\src" `
    -o "$BUILD\keccak256_cuda.obj" `
    "--generate-code=arch=compute_86,code=sm_86" `
    "--generate-code=arch=compute_89,code=sm_89" `
    "--generate-code=arch=compute_120,code=sm_120" `
    -O2 -w `
    -Xcompiler "/utf-8"

if ($LASTEXITCODE -ne 0) {
    Write-Host "CUDA compilation failed" -ForegroundColor Red
    exit 1
}

# Step 3: Compile GPU miner C files
Write-Host "`n[3/4] Compiling GPU miner..." -ForegroundColor Yellow

$includes = "/I`"$SRC\include`" /I`"$SRC\src`" /I`"$CUDA_INCLUDE`""
$defines = "/DFTC_WINDOWS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DFTC_HAS_CUDA"
$flags = "/O2 /MD /c /utf-8"

& cl.exe $flags $defines $includes "$SRC\src\miner\gpu_miner.c" "/Fo$BUILD\gpu_miner.obj"
& cl.exe $flags $defines $includes "$SRC\src\miner\keccak256_opencl.c" "/Fo$BUILD\keccak256_opencl.obj"
& cl.exe $flags $defines $includes "$SRC\node\gpu_miner_main.c" "/Fo$BUILD\gpu_miner_main.obj"

# Step 4: Link everything
Write-Host "`n[4/4] Linking ftc-miner-gpu.exe..." -ForegroundColor Yellow
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
