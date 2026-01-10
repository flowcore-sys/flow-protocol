#!/bin/bash
set -e

SRC_DIR="/mnt/c/Flow Protocol"
BUILD_DIR="$SRC_DIR/build_wsl"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo ""
echo "=== Compiling FTC Node (Linux) ==="
gcc -c -O2 -I"$SRC_DIR/include" -I"$SRC_DIR/src" \
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
    "$SRC_DIR/src/stratum/stratum.c" \
    "$SRC_DIR/src/p2pool/p2pool.c" \
    "$SRC_DIR/src/p2p/p2p.c" \
    "$SRC_DIR/node/full_node.c" \
    "$SRC_DIR/node/main.c"

echo ""
echo "=== Linking ==="
gcc -o ftc-node *.o -lpthread

echo ""
echo "=== SUCCESS ==="
cp ftc-node "$SRC_DIR/ftc-node-linux"
echo "Built: $SRC_DIR/ftc-node-linux"
