#!/bin/bash
set -e

CUDA_PATH=/usr/local/cuda-12.8
SRC_DIR="/mnt/c/Flow Protocol"
BUILD_DIR="$SRC_DIR/build-linux"

export PATH=$CUDA_PATH/bin:$PATH

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Compiling CUDA kernel..."
$CUDA_PATH/bin/nvcc -c "$SRC_DIR/src/miner/keccak256_cuda.cu" -o keccak256_cuda.o \
    -I"$SRC_DIR/include" -I"$SRC_DIR/src" \
    -gencode=arch=compute_75,code=sm_75 \
    -gencode=arch=compute_86,code=sm_86 \
    -gencode=arch=compute_89,code=sm_89 \
    -O3 -DFTC_HAS_CUDA

echo "Compiling C files..."
gcc -c -O2 -I"$SRC_DIR/include" -I"$SRC_DIR/src" -I"$CUDA_PATH/include" \
    -DFTC_HAS_CUDA \
    "$SRC_DIR/src/crypto/keccak256.c" \
    "$SRC_DIR/src/crypto/tweetnacl.c" \
    "$SRC_DIR/src/crypto/ed25519.c" \
    "$SRC_DIR/src/crypto/keys.c" \
    "$SRC_DIR/src/crypto/merkle.c" \
    "$SRC_DIR/src/core/block.c" \
    "$SRC_DIR/src/core/tx.c" \
    "$SRC_DIR/src/core/utxo.c" \
    "$SRC_DIR/src/core/consensus.c" \
    "$SRC_DIR/src/core/mempool.c" \
    "$SRC_DIR/src/rpc/rpc.c" \
    "$SRC_DIR/src/wallet/wallet.c" \
    "$SRC_DIR/src/miner/miner.c" \
    "$SRC_DIR/src/miner/gpu_miner.c" \
    "$SRC_DIR/node/gpu_miner_main.c"

echo "Linking..."
g++ -o ftc-miner-gpu *.o \
    -L"$CUDA_PATH/lib64" -lcudart_static -lpthread -ldl -lrt

echo ""
echo "SUCCESS! Binary: $BUILD_DIR/ftc-miner-gpu"
cp ftc-miner-gpu "$SRC_DIR/release/ftc-miner-gpu-linux"
echo "Copied to release/ftc-miner-gpu-linux"
