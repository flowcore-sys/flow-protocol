/**
 * FTC CUDA Keccak-256 Mining Kernel
 *
 * High-performance GPU mining for NVIDIA cards.
 * Implements double Keccak-256 for FTC Proof of Work.
 */

#include "gpu_miner.h"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define FTC_NVML_AVAILABLE 0
#else
#include <sys/time.h>
#define FTC_NVML_AVAILABLE 0
#endif

/*==============================================================================
 * KECCAK CONSTANTS (device memory)
 *============================================================================*/

__constant__ uint64_t d_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*==============================================================================
 * KECCAK-F[1600] DEVICE IMPLEMENTATION
 *============================================================================*/

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

__device__ __forceinline__ void keccak_f1600(uint64_t* state)
{
    uint64_t t, bc[5];

    #pragma unroll
    for (int round = 0; round < 24; round++) {
        /* Theta */
        bc[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        bc[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        bc[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        bc[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        bc[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        t = bc[4] ^ ROTL64(bc[1], 1);
        state[0] ^= t; state[5] ^= t; state[10] ^= t; state[15] ^= t; state[20] ^= t;
        t = bc[0] ^ ROTL64(bc[2], 1);
        state[1] ^= t; state[6] ^= t; state[11] ^= t; state[16] ^= t; state[21] ^= t;
        t = bc[1] ^ ROTL64(bc[3], 1);
        state[2] ^= t; state[7] ^= t; state[12] ^= t; state[17] ^= t; state[22] ^= t;
        t = bc[2] ^ ROTL64(bc[4], 1);
        state[3] ^= t; state[8] ^= t; state[13] ^= t; state[18] ^= t; state[23] ^= t;
        t = bc[3] ^ ROTL64(bc[0], 1);
        state[4] ^= t; state[9] ^= t; state[14] ^= t; state[19] ^= t; state[24] ^= t;

        /* Rho + Pi */
        t = state[1];
        state[1]  = ROTL64(state[6], 44);
        state[6]  = ROTL64(state[9], 20);
        state[9]  = ROTL64(state[22], 61);
        state[22] = ROTL64(state[14], 39);
        state[14] = ROTL64(state[20], 18);
        state[20] = ROTL64(state[2], 62);
        state[2]  = ROTL64(state[12], 43);
        state[12] = ROTL64(state[13], 25);
        state[13] = ROTL64(state[19], 8);
        state[19] = ROTL64(state[23], 56);
        state[23] = ROTL64(state[15], 41);
        state[15] = ROTL64(state[4], 27);
        state[4]  = ROTL64(state[24], 14);
        state[24] = ROTL64(state[21], 2);
        state[21] = ROTL64(state[8], 55);
        state[8]  = ROTL64(state[16], 45);
        state[16] = ROTL64(state[5], 36);
        state[5]  = ROTL64(state[3], 28);
        state[3]  = ROTL64(state[18], 21);
        state[18] = ROTL64(state[17], 15);
        state[17] = ROTL64(state[11], 10);
        state[11] = ROTL64(state[7], 6);
        state[7]  = ROTL64(state[10], 3);
        state[10] = ROTL64(t, 1);

        /* Chi */
        bc[0] = state[0]; bc[1] = state[1]; bc[2] = state[2]; bc[3] = state[3]; bc[4] = state[4];
        state[0] ^= (~bc[1]) & bc[2];
        state[1] ^= (~bc[2]) & bc[3];
        state[2] ^= (~bc[3]) & bc[4];
        state[3] ^= (~bc[4]) & bc[0];
        state[4] ^= (~bc[0]) & bc[1];

        bc[0] = state[5]; bc[1] = state[6]; bc[2] = state[7]; bc[3] = state[8]; bc[4] = state[9];
        state[5] ^= (~bc[1]) & bc[2];
        state[6] ^= (~bc[2]) & bc[3];
        state[7] ^= (~bc[3]) & bc[4];
        state[8] ^= (~bc[4]) & bc[0];
        state[9] ^= (~bc[0]) & bc[1];

        bc[0] = state[10]; bc[1] = state[11]; bc[2] = state[12]; bc[3] = state[13]; bc[4] = state[14];
        state[10] ^= (~bc[1]) & bc[2];
        state[11] ^= (~bc[2]) & bc[3];
        state[12] ^= (~bc[3]) & bc[4];
        state[13] ^= (~bc[4]) & bc[0];
        state[14] ^= (~bc[0]) & bc[1];

        bc[0] = state[15]; bc[1] = state[16]; bc[2] = state[17]; bc[3] = state[18]; bc[4] = state[19];
        state[15] ^= (~bc[1]) & bc[2];
        state[16] ^= (~bc[2]) & bc[3];
        state[17] ^= (~bc[3]) & bc[4];
        state[18] ^= (~bc[4]) & bc[0];
        state[19] ^= (~bc[0]) & bc[1];

        bc[0] = state[20]; bc[1] = state[21]; bc[2] = state[22]; bc[3] = state[23]; bc[4] = state[24];
        state[20] ^= (~bc[1]) & bc[2];
        state[21] ^= (~bc[2]) & bc[3];
        state[22] ^= (~bc[3]) & bc[4];
        state[23] ^= (~bc[4]) & bc[0];
        state[24] ^= (~bc[0]) & bc[1];

        /* Iota */
        state[0] ^= d_RC[round];
    }
}

/*==============================================================================
 * KECCAK-256 HASH (80-byte input)
 *============================================================================*/

__device__ __forceinline__ void keccak256_80(const uint8_t* data, uint8_t* hash)
{
    uint64_t state[25] = {0};

    /* Absorb 80 bytes (rate = 136 bytes) */
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        state[i] = ((uint64_t*)data)[i];
    }

    /* Padding: 0x01 at byte 80, 0x80 at byte 135 */
    state[10] ^= 0x01;
    state[16] ^= 0x8000000000000000ULL;

    keccak_f1600(state);

    /* Extract 256 bits */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        ((uint64_t*)hash)[i] = state[i];
    }
}

/*==============================================================================
 * KECCAK-256 HASH (32-byte input)
 *============================================================================*/

__device__ __forceinline__ void keccak256_32(const uint8_t* data, uint8_t* hash)
{
    uint64_t state[25] = {0};

    /* Absorb 32 bytes */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        state[i] = ((uint64_t*)data)[i];
    }

    /* Padding: 0x01 at byte 32, 0x80 at byte 135 */
    state[4] ^= 0x01;
    state[16] ^= 0x8000000000000000ULL;

    keccak_f1600(state);

    /* Extract 256 bits */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        ((uint64_t*)hash)[i] = state[i];
    }
}

/*==============================================================================
 * DOUBLE KECCAK-256 MINING KERNEL
 *============================================================================*/

__global__ void keccak256_mine_kernel(
    const uint8_t* __restrict__ header,     /* 80-byte header (nonce at 76-79) */
    const uint8_t* __restrict__ target,     /* 32-byte target */
    uint32_t nonce_start,
    uint32_t* result_nonce,
    uint8_t* result_hash,
    uint32_t* found
)
{
    uint32_t nonce = nonce_start + blockIdx.x * blockDim.x + threadIdx.x;

    /* Copy header to aligned local memory and set nonce */
    /* Use uint64_t array for proper 8-byte alignment (required for Keccak) */
    uint64_t local_header_u64[10];
    uint8_t* local_header = (uint8_t*)local_header_u64;

    #pragma unroll
    for (int i = 0; i < 76; i++) {
        local_header[i] = header[i];
    }
    local_header[76] = (uint8_t)(nonce);
    local_header[77] = (uint8_t)(nonce >> 8);
    local_header[78] = (uint8_t)(nonce >> 16);
    local_header[79] = (uint8_t)(nonce >> 24);

    /* Double Keccak-256 */
    uint64_t hash1_u64[4], hash2_u64[4];
    uint8_t* hash1 = (uint8_t*)hash1_u64;
    uint8_t* hash2 = (uint8_t*)hash2_u64;
    keccak256_80(local_header, hash1);
    keccak256_32(hash1, hash2);

    /* Compare with target (big-endian comparison) */
    bool valid = true;
    #pragma unroll
    for (int i = 31; i >= 0; i--) {
        if (hash2[i] < target[i]) break;
        if (hash2[i] > target[i]) { valid = false; break; }
    }

    if (valid) {
        if (atomicCAS(found, 0, 1) == 0) {
            *result_nonce = nonce;
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                result_hash[i] = hash2[i];
            }
        }
    }
}

/*==============================================================================
 * CUDA CONTEXT STRUCTURE
 *============================================================================*/

struct ftc_gpu_ctx {
    int             device_id;
    ftc_gpu_device_t device;
    uint32_t        batch_size;

    /* Device memory */
    uint8_t*        d_header;
    uint8_t*        d_target;
    uint32_t*       d_result_nonce;
    uint8_t*        d_result_hash;
    uint32_t*       d_found;

    /* Host memory */
    uint8_t         h_header[80];
    uint8_t         h_target[32];

    /* Statistics */
    uint64_t        total_hashes;
    double          last_hashrate;
    double          last_elapsed;

    cudaStream_t    stream;
    cudaEvent_t     start_event;
    cudaEvent_t     stop_event;
};

/*==============================================================================
 * GLOBAL STATE
 *============================================================================*/

static ftc_gpu_device_t g_cuda_devices[FTC_GPU_MAX_DEVICES];
static int g_cuda_device_count = 0;
static bool g_cuda_initialized = false;

/*==============================================================================
 * CUDA ERROR HANDLING
 *============================================================================*/

#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error: %s at %s:%d\n", \
                cudaGetErrorString(err), __FILE__, __LINE__); \
        return false; \
    } \
} while(0)

#define CUDA_CHECK_NULL(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error: %s at %s:%d\n", \
                cudaGetErrorString(err), __FILE__, __LINE__); \
        return NULL; \
    } \
} while(0)

/*==============================================================================
 * DEVICE ENUMERATION (CUDA)
 *============================================================================*/

extern "C" int ftc_gpu_init_cuda(void)
{
    if (g_cuda_initialized) return g_cuda_device_count;

    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess || count == 0) {
        g_cuda_initialized = true;
        return 0;
    }

    for (int i = 0; i < count && g_cuda_device_count < FTC_GPU_MAX_DEVICES; i++) {
        cudaDeviceProp prop;
        if (cudaGetDeviceProperties(&prop, i) != cudaSuccess) continue;

        ftc_gpu_device_t* dev = &g_cuda_devices[g_cuda_device_count];
        dev->id = g_cuda_device_count;
        dev->type = FTC_GPU_CUDA;
        strncpy(dev->name, prop.name, sizeof(dev->name) - 1);
        strncpy(dev->vendor, "NVIDIA", sizeof(dev->vendor) - 1);
        dev->memory_total = prop.totalGlobalMem;
        dev->memory_free = prop.totalGlobalMem;  /* Approximation */
        dev->compute_units = prop.multiProcessorCount;

        /* Get clock rate via attribute (removed from struct in CUDA 13) */
        int clock_khz = 0;
        cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, i);
        dev->clock_mhz = clock_khz / 1000;

        dev->pci_bus = prop.pciBusID;
        dev->pci_device = prop.pciDeviceID;
        dev->power_limit = 0;  /* Requires NVML */
        dev->temperature = 0;  /* Requires NVML */
        dev->available = true;

        g_cuda_device_count++;
    }

    g_cuda_initialized = true;
    return g_cuda_device_count;
}

extern "C" void ftc_gpu_shutdown_cuda(void)
{
    cudaDeviceReset();
    g_cuda_initialized = false;
    g_cuda_device_count = 0;
}

extern "C" const ftc_gpu_device_t* ftc_gpu_get_cuda_device(int idx)
{
    if (idx < 0 || idx >= g_cuda_device_count) return NULL;
    return &g_cuda_devices[idx];
}

extern "C" int ftc_gpu_cuda_count(void)
{
    return g_cuda_device_count;
}

/*==============================================================================
 * MINING CONTEXT (CUDA)
 *============================================================================*/

extern "C" ftc_gpu_ctx_t* ftc_gpu_ctx_new_cuda(int device_id, uint32_t batch_size)
{
    if (device_id < 0 || device_id >= g_cuda_device_count) return NULL;

    CUDA_CHECK_NULL(cudaSetDevice(device_id));

    ftc_gpu_ctx_t* ctx = (ftc_gpu_ctx_t*)calloc(1, sizeof(ftc_gpu_ctx_t));
    if (!ctx) return NULL;

    ctx->device_id = device_id;
    ctx->device = g_cuda_devices[device_id];
    ctx->batch_size = batch_size > 0 ? batch_size : FTC_GPU_BATCH_SIZE;

    /* Allocate device memory */
    CUDA_CHECK_NULL(cudaMalloc(&ctx->d_header, 80));
    CUDA_CHECK_NULL(cudaMalloc(&ctx->d_target, 32));
    CUDA_CHECK_NULL(cudaMalloc(&ctx->d_result_nonce, sizeof(uint32_t)));
    CUDA_CHECK_NULL(cudaMalloc(&ctx->d_result_hash, 32));
    CUDA_CHECK_NULL(cudaMalloc(&ctx->d_found, sizeof(uint32_t)));

    /* Create stream and events for timing */
    CUDA_CHECK_NULL(cudaStreamCreate(&ctx->stream));
    CUDA_CHECK_NULL(cudaEventCreate(&ctx->start_event));
    CUDA_CHECK_NULL(cudaEventCreate(&ctx->stop_event));

    return ctx;
}

extern "C" void ftc_gpu_ctx_free_cuda(ftc_gpu_ctx_t* ctx)
{
    if (!ctx) return;

    cudaSetDevice(ctx->device_id);

    if (ctx->d_header) cudaFree(ctx->d_header);
    if (ctx->d_target) cudaFree(ctx->d_target);
    if (ctx->d_result_nonce) cudaFree(ctx->d_result_nonce);
    if (ctx->d_result_hash) cudaFree(ctx->d_result_hash);
    if (ctx->d_found) cudaFree(ctx->d_found);

    if (ctx->stream) cudaStreamDestroy(ctx->stream);
    if (ctx->start_event) cudaEventDestroy(ctx->start_event);
    if (ctx->stop_event) cudaEventDestroy(ctx->stop_event);

    free(ctx);
}

/*==============================================================================
 * MINING OPERATIONS (CUDA)
 *============================================================================*/

extern "C" bool ftc_gpu_set_work_cuda(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32])
{
    if (!ctx) return false;

    CUDA_CHECK(cudaSetDevice(ctx->device_id));

    memcpy(ctx->h_header, header, 80);
    memcpy(ctx->h_target, target, 32);

    CUDA_CHECK(cudaMemcpyAsync(ctx->d_header, header, 80, cudaMemcpyHostToDevice, ctx->stream));
    CUDA_CHECK(cudaMemcpyAsync(ctx->d_target, target, 32, cudaMemcpyHostToDevice, ctx->stream));

    return true;
}

extern "C" ftc_gpu_result_t ftc_gpu_mine_cuda(ftc_gpu_ctx_t* ctx, uint32_t nonce_start)
{
    ftc_gpu_result_t result = {0};
    if (!ctx) return result;

    cudaSetDevice(ctx->device_id);

    /* Reset found flag */
    uint32_t zero = 0;
    cudaMemcpyAsync(ctx->d_found, &zero, sizeof(uint32_t), cudaMemcpyHostToDevice, ctx->stream);

    /* Calculate grid dimensions */
    int threads_per_block = 256;
    int blocks = (ctx->batch_size + threads_per_block - 1) / threads_per_block;

    /* Start timing */
    cudaEventRecord(ctx->start_event, ctx->stream);

    /* Launch kernel */
    keccak256_mine_kernel<<<blocks, threads_per_block, 0, ctx->stream>>>(
        ctx->d_header,
        ctx->d_target,
        nonce_start,
        ctx->d_result_nonce,
        ctx->d_result_hash,
        ctx->d_found
    );

    /* Check for kernel launch error */
    cudaError_t launch_err = cudaGetLastError();
    if (launch_err != cudaSuccess) {
        fprintf(stderr, "CUDA kernel launch error: %s\n", cudaGetErrorString(launch_err));
    }

    /* Stop timing */
    cudaEventRecord(ctx->stop_event, ctx->stream);
    cudaError_t sync_err = cudaStreamSynchronize(ctx->stream);
    if (sync_err != cudaSuccess) {
        fprintf(stderr, "CUDA sync error: %s\n", cudaGetErrorString(sync_err));
    }

    /* Get elapsed time */
    float elapsed_ms = 0;
    cudaEventElapsedTime(&elapsed_ms, ctx->start_event, ctx->stop_event);

    /* Check result */
    uint32_t found = 0;
    cudaMemcpy(&found, ctx->d_found, sizeof(uint32_t), cudaMemcpyDeviceToHost);

    result.hashes = ctx->batch_size;
    result.elapsed_ms = elapsed_ms;

    if (found) {
        result.found = true;
        cudaMemcpy(&result.nonce, ctx->d_result_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(result.hash, ctx->d_result_hash, 32, cudaMemcpyDeviceToHost);
    }

    /* Update stats */
    ctx->total_hashes += ctx->batch_size;
    ctx->last_elapsed = elapsed_ms;
    if (elapsed_ms > 0) {
        ctx->last_hashrate = (double)ctx->batch_size * 1000.0 / elapsed_ms;
    }

    return result;
}

extern "C" double ftc_gpu_get_hashrate_cuda(ftc_gpu_ctx_t* ctx)
{
    return ctx ? ctx->last_hashrate : 0;
}

extern "C" uint64_t ftc_gpu_get_total_hashes_cuda(ftc_gpu_ctx_t* ctx)
{
    return ctx ? ctx->total_hashes : 0;
}

extern "C" void ftc_gpu_update_stats_cuda(ftc_gpu_ctx_t* ctx)
{
    if (!ctx) return;
    /* NVML would be used here for temperature/power monitoring */
}
