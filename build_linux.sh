#!/bin/bash
export PATH=/usr/local/cuda-13.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CUDACXX=/usr/local/cuda-13.1/bin/nvcc
cd "/mnt/c/Flow Protocol"
rm -rf build-linux/CMakeCache.txt build-linux/CMakeFiles
cd build-linux
cmake .. -DFTC_BUILD_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES="75;86;89;100;120"
make ftc-miner-gpu -j4
