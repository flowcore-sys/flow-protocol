#!/bin/bash
export PATH=/usr/local/cuda-12.8/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/c/Flow\ Protocol
rm -rf build-linux/CMakeCache.txt build-linux/CMakeFiles
cd build-linux
cmake .. -DFTC_BUILD_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES="75;86;89;100;110"
make ftc-miner-gpu -j4
