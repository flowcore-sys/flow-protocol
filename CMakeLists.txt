cmake_minimum_required(VERSION 3.16)
project(ftc-protocol C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(FTC_BUILD_TESTS "Build tests" ON)
option(FTC_BUILD_TOOLS "Build CLI tools" ON)
option(FTC_BUILD_CUDA "Build CUDA GPU miner (NVIDIA)" OFF)
option(FTC_BUILD_OPENCL "Build OpenCL GPU miner (AMD/Intel)" OFF)
option(FTC_USE_LEVELDB "Use LevelDB for storage" ON)

# Compiler flags
if(MSVC)
    add_compile_options(/W3 /D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3)
    endif()
endif()

# Platform detection
if(WIN32)
    add_definitions(-DFTC_WINDOWS)
elseif(APPLE)
    add_definitions(-DFTC_MACOS)
else()
    add_definitions(-DFTC_LINUX)
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Core library sources
set(FTC_CORE_SOURCES
    src/crypto/keccak256.c
    src/crypto/ed25519.c
    src/crypto/keys.c
    src/crypto/merkle.c
    src/core/block.c
    src/core/tx.c
    src/core/utxo.c
    src/core/consensus.c
    src/core/mempool.c
)

# Network sources
set(FTC_NETWORK_SOURCES
    src/network/protocol.c
    src/network/p2p.c
)

# Storage sources (when implemented)
set(FTC_STORAGE_SOURCES
    # src/storage/db.c
    # src/storage/indexes.c
)

# RPC sources
set(FTC_RPC_SOURCES
    src/rpc/rpc.c
)

# Wallet sources
set(FTC_WALLET_SOURCES
    src/wallet/wallet.c
)

# Node sources (when implemented)
set(FTC_NODE_SOURCES
    # src/node/node.c
    # src/node/config.c
)

# Miner sources
set(FTC_MINER_SOURCES
    src/miner/miner.c
)

# GPU Miner sources (common)
set(FTC_GPU_MINER_SOURCES
    src/miner/gpu_miner.c
    src/miner/keccak256_opencl.c
)

# Core library
add_library(ftc-core STATIC
    ${FTC_CORE_SOURCES}
    ${FTC_NETWORK_SOURCES}
    ${FTC_RPC_SOURCES}
    ${FTC_WALLET_SOURCES}
    ${FTC_MINER_SOURCES}
)

# Link libraries based on platform
if(WIN32)
    target_link_libraries(ftc-core bcrypt ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(ftc-core Threads::Threads)
endif()

# LevelDB (optional)
if(FTC_USE_LEVELDB)
    find_package(leveldb QUIET)
    if(leveldb_FOUND)
        target_link_libraries(ftc-core leveldb::leveldb)
        target_compile_definitions(ftc-core PRIVATE FTC_HAS_LEVELDB)
    else()
        message(STATUS "LevelDB not found - storage will use file-based fallback")
    endif()
endif()

#==============================================================================
# GPU Mining Support
#==============================================================================

# CUDA Support (NVIDIA)
if(FTC_BUILD_CUDA)
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)

    message(STATUS "CUDA found - building NVIDIA GPU miner")

    set(FTC_CUDA_SOURCES
        src/miner/keccak256_cuda.cu
    )

    add_library(ftc-cuda STATIC
        ${FTC_CUDA_SOURCES}
    )

    target_include_directories(ftc-cuda PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(ftc-cuda CUDA::cudart)
    set_target_properties(ftc-cuda PROPERTIES CUDA_SEPARABLE_COMPILATION OFF)

    # Set CUDA architectures (CUDA 13+ requires compute_75+)
    set_target_properties(ftc-cuda PROPERTIES CUDA_ARCHITECTURES "89")

    # Fix CUDA 13.x nvcc issues with MSVC flags
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler=/wd4996")
    set(CMAKE_CUDA_FLAGS_RELEASE "-O3")

    # Disable PDB for CUDA (fixes nvcc comma parsing bug)
    set(CMAKE_CUDA_COMPILE_OBJECT "<CMAKE_CUDA_COMPILER> <DEFINES> <INCLUDES> <FLAGS> -c <SOURCE> -o <OBJECT>")
endif()

# OpenCL Support (AMD/Intel)
if(FTC_BUILD_OPENCL)
    find_package(OpenCL)

    if(OpenCL_FOUND)
        message(STATUS "OpenCL found - building AMD/Intel GPU miner")
        add_definitions(-DFTC_HAS_OPENCL)
    else()
        message(WARNING "OpenCL not found - AMD/Intel GPU mining disabled")
        set(FTC_BUILD_OPENCL OFF)
    endif()
endif()

# GPU Miner Library (combines CUDA and OpenCL)
if(FTC_BUILD_CUDA OR FTC_BUILD_OPENCL)
    add_library(ftc-gpu STATIC
        ${FTC_GPU_MINER_SOURCES}
    )

    target_include_directories(ftc-gpu PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

    if(FTC_BUILD_CUDA)
        target_compile_definitions(ftc-gpu PRIVATE FTC_HAS_CUDA)
        target_link_libraries(ftc-gpu ftc-cuda)
    endif()

    if(FTC_BUILD_OPENCL)
        target_compile_definitions(ftc-gpu PRIVATE FTC_HAS_OPENCL)
        target_link_libraries(ftc-gpu OpenCL::OpenCL)
    endif()

    if(WIN32)
        target_link_libraries(ftc-gpu ws2_32)
    endif()

    # GPU Miner executable
    add_executable(ftc-miner-gpu
        node/gpu_miner_main.c
    )
    target_link_libraries(ftc-miner-gpu ftc-core ftc-gpu)

    if(FTC_BUILD_CUDA)
        target_compile_definitions(ftc-miner-gpu PRIVATE FTC_HAS_CUDA)
    endif()
    if(FTC_BUILD_OPENCL)
        target_compile_definitions(ftc-miner-gpu PRIVATE FTC_HAS_OPENCL)
    endif()
endif()

#==============================================================================
# Standard Tools
#==============================================================================

# Genesis miner tool
add_executable(ftc-genesis
    tools/genesis_miner.c
)
target_link_libraries(ftc-genesis ftc-core)

# Address generator tool
add_executable(ftc-genaddr
    tools/genaddr.c
)
target_link_libraries(ftc-genaddr ftc-core)

# Full node
add_executable(ftc-node
    node/full_node.c
    node/main.c
)
target_link_libraries(ftc-node ftc-core)

# Standalone CPU miner
add_executable(ftc-miner
    node/miner_node.c
)
target_link_libraries(ftc-miner ftc-core)

#==============================================================================
# Tests
#==============================================================================

if(FTC_BUILD_TESTS)
    enable_testing()

    # Crypto tests
    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto ftc-core)
    add_test(NAME crypto COMMAND test_crypto)

    # Block tests
    add_executable(test_block tests/test_block.c)
    target_link_libraries(test_block ftc-core)
    add_test(NAME block COMMAND test_block)

    # Transaction tests
    add_executable(test_tx tests/test_tx.c)
    target_link_libraries(test_tx ftc-core)
    add_test(NAME tx COMMAND test_tx)
endif()

#==============================================================================
# Install
#==============================================================================

install(TARGETS ftc-core DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

if(FTC_BUILD_CUDA OR FTC_BUILD_OPENCL)
    install(TARGETS ftc-miner-gpu DESTINATION bin)
    # Install OpenCL kernel file
    install(FILES src/miner/keccak256.cl DESTINATION share/ftc)
endif()

#==============================================================================
# Build Summary
#==============================================================================

message(STATUS "")
message(STATUS "=== FTC Protocol Build Configuration ===")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "Tests:          ${FTC_BUILD_TESTS}")
message(STATUS "CUDA (NVIDIA):  ${FTC_BUILD_CUDA}")
message(STATUS "OpenCL (AMD):   ${FTC_BUILD_OPENCL}")
message(STATUS "LevelDB:        ${FTC_USE_LEVELDB}")
message(STATUS "")
