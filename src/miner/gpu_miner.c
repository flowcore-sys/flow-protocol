/**
 * FTC GPU Mining - Unified Interface
 *
 * Combines CUDA and OpenCL implementations into single API.
 * Handles multi-GPU farming with automatic nonce distribution.
 */

#include "gpu_miner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#endif

/*==============================================================================
 * EXTERNAL DECLARATIONS (CUDA)
 *============================================================================*/

#ifdef FTC_HAS_CUDA
extern int ftc_gpu_init_cuda(void);
extern void ftc_gpu_shutdown_cuda(void);
extern const ftc_gpu_device_t* ftc_gpu_get_cuda_device(int idx);
extern int ftc_gpu_cuda_count(void);
extern ftc_gpu_ctx_t* ftc_gpu_ctx_new_cuda(int device_id, uint32_t batch_size);
extern void ftc_gpu_ctx_free_cuda(ftc_gpu_ctx_t* ctx);
extern bool ftc_gpu_set_work_cuda(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32]);
extern void ftc_gpu_launch_cuda(ftc_gpu_ctx_t* ctx, uint32_t nonce_start);
extern ftc_gpu_result_t ftc_gpu_sync_cuda(ftc_gpu_ctx_t* ctx);
extern ftc_gpu_result_t ftc_gpu_mine_cuda(ftc_gpu_ctx_t* ctx, uint32_t nonce_start);
extern double ftc_gpu_get_hashrate_cuda(ftc_gpu_ctx_t* ctx);
extern uint64_t ftc_gpu_get_total_hashes_cuda(ftc_gpu_ctx_t* ctx);
extern void ftc_gpu_update_stats_cuda(ftc_gpu_ctx_t* ctx);
#else
static int ftc_gpu_init_cuda(void) { return 0; }
static void ftc_gpu_shutdown_cuda(void) {}
static const ftc_gpu_device_t* ftc_gpu_get_cuda_device(int idx) { (void)idx; return NULL; }
static int ftc_gpu_cuda_count(void) { return 0; }
static ftc_gpu_ctx_t* ftc_gpu_ctx_new_cuda(int device_id, uint32_t batch_size) { (void)device_id; (void)batch_size; return NULL; }
static void ftc_gpu_ctx_free_cuda(ftc_gpu_ctx_t* ctx) { (void)ctx; }
static bool ftc_gpu_set_work_cuda(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32]) { (void)ctx; (void)header; (void)target; return false; }
static void ftc_gpu_launch_cuda(ftc_gpu_ctx_t* ctx, uint32_t nonce_start) { (void)ctx; (void)nonce_start; }
static ftc_gpu_result_t ftc_gpu_sync_cuda(ftc_gpu_ctx_t* ctx) { (void)ctx; ftc_gpu_result_t r = {0}; return r; }
static ftc_gpu_result_t ftc_gpu_mine_cuda(ftc_gpu_ctx_t* ctx, uint32_t nonce_start) { (void)ctx; (void)nonce_start; ftc_gpu_result_t r = {0}; return r; }
static double ftc_gpu_get_hashrate_cuda(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
static uint64_t ftc_gpu_get_total_hashes_cuda(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
static void ftc_gpu_update_stats_cuda(ftc_gpu_ctx_t* ctx) { (void)ctx; }
#endif

/*==============================================================================
 * EXTERNAL DECLARATIONS (OpenCL) - DISABLED
 *============================================================================*/

/* OpenCL removed - CUDA only */
static int ftc_gpu_init_opencl(void) { return 0; }
static void ftc_gpu_shutdown_opencl(void) {}
static const ftc_gpu_device_t* ftc_gpu_get_opencl_device(int idx) { (void)idx; return NULL; }
static int ftc_gpu_opencl_count(void) { return 0; }
static ftc_gpu_ctx_t* ftc_gpu_ctx_new_opencl(int device_id, uint32_t batch_size) { (void)device_id; (void)batch_size; return NULL; }
static void ftc_gpu_ctx_free_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; }
static bool ftc_gpu_set_work_opencl(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32]) { (void)ctx; (void)header; (void)target; return false; }
static ftc_gpu_result_t ftc_gpu_mine_opencl(ftc_gpu_ctx_t* ctx, uint32_t nonce_start) { (void)ctx; (void)nonce_start; ftc_gpu_result_t r = {0}; return r; }
static double ftc_gpu_get_hashrate_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
static uint64_t ftc_gpu_get_total_hashes_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
static void ftc_gpu_update_stats_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; }

/*==============================================================================
 * UNIFIED DEVICE LIST
 *============================================================================*/

static ftc_gpu_device_t g_all_devices[FTC_GPU_MAX_DEVICES];
static int g_device_count = 0;
static bool g_initialized = false;

/* Map unified device ID to backend */
typedef struct {
    ftc_gpu_type_t type;
    int backend_id;     /* Device ID within CUDA or OpenCL backend */
} device_mapping_t;

static device_mapping_t g_device_map[FTC_GPU_MAX_DEVICES];

/*==============================================================================
 * PUBLIC API - DEVICE ENUMERATION
 *============================================================================*/

int ftc_gpu_init(void)
{
    if (g_initialized) return g_device_count;

    g_device_count = 0;

    /* Initialize CUDA devices */
    int cuda_count = ftc_gpu_init_cuda();
    for (int i = 0; i < cuda_count && g_device_count < FTC_GPU_MAX_DEVICES; i++) {
        const ftc_gpu_device_t* dev = ftc_gpu_get_cuda_device(i);
        if (dev) {
            g_all_devices[g_device_count] = *dev;
            g_all_devices[g_device_count].id = g_device_count;
            g_device_map[g_device_count].type = FTC_GPU_CUDA;
            g_device_map[g_device_count].backend_id = i;
            g_device_count++;
        }
    }

    /* Initialize OpenCL devices */
    int opencl_count = ftc_gpu_init_opencl();
    for (int i = 0; i < opencl_count && g_device_count < FTC_GPU_MAX_DEVICES; i++) {
        const ftc_gpu_device_t* dev = ftc_gpu_get_opencl_device(i);
        if (dev) {
            /* Check if this device is already in the list (e.g., NVIDIA via both CUDA and OpenCL) */
            bool duplicate = false;
            for (int j = 0; j < g_device_count; j++) {
                if (strcmp(g_all_devices[j].name, dev->name) == 0 &&
                    g_all_devices[j].memory_total == dev->memory_total) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate) {
                g_all_devices[g_device_count] = *dev;
                g_all_devices[g_device_count].id = g_device_count;
                g_device_map[g_device_count].type = FTC_GPU_OPENCL;
                g_device_map[g_device_count].backend_id = i;
                g_device_count++;
            }
        }
    }

    g_initialized = true;
    return g_device_count;
}

void ftc_gpu_shutdown(void)
{
    ftc_gpu_shutdown_cuda();
    ftc_gpu_shutdown_opencl();
    g_initialized = false;
    g_device_count = 0;
}

int ftc_gpu_device_count(void)
{
    return g_device_count;
}

const ftc_gpu_device_t* ftc_gpu_get_device(int device_id)
{
    if (device_id < 0 || device_id >= g_device_count) return NULL;
    return &g_all_devices[device_id];
}

void ftc_gpu_print_devices(void)
{
    printf("  Detected %d GPU(s):\n", g_device_count);

    for (int i = 0; i < g_device_count; i++) {
        const ftc_gpu_device_t* dev = &g_all_devices[i];
        const char* type_str = (dev->type == FTC_GPU_CUDA) ? "CUDA" : "OpenCL";

        printf("  [%d] %s (%s)\n", i, dev->name, type_str);
        printf("      %s | %d CUs @ %d MHz | %.0f MB\n",
               dev->vendor,
               dev->compute_units,
               dev->clock_mhz,
               dev->memory_total / (1024.0 * 1024.0));
    }
}

/*==============================================================================
 * UNIFIED CONTEXT WRAPPER
 *============================================================================*/

typedef struct ftc_gpu_ctx_wrapper {
    ftc_gpu_type_t  type;
    ftc_gpu_ctx_t*  backend_ctx;
    ftc_gpu_device_t device;
    uint32_t        batch_size;
    uint32_t        pending_nonce;  /* For OpenCL async emulation */
} ftc_gpu_ctx_wrapper_t;

ftc_gpu_ctx_t* ftc_gpu_ctx_new(int device_id, uint32_t batch_size)
{
    if (device_id < 0 || device_id >= g_device_count) return NULL;

    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)calloc(1, sizeof(ftc_gpu_ctx_wrapper_t));
    if (!wrapper) return NULL;

    wrapper->type = g_device_map[device_id].type;
    wrapper->device = g_all_devices[device_id];
    wrapper->batch_size = batch_size > 0 ? batch_size : FTC_GPU_BATCH_SIZE;

    int backend_id = g_device_map[device_id].backend_id;

    if (wrapper->type == FTC_GPU_CUDA) {
        wrapper->backend_ctx = ftc_gpu_ctx_new_cuda(backend_id, wrapper->batch_size);
    } else {
        wrapper->backend_ctx = ftc_gpu_ctx_new_opencl(backend_id, wrapper->batch_size);
    }

    if (!wrapper->backend_ctx) {
        free(wrapper);
        return NULL;
    }

    return (ftc_gpu_ctx_t*)wrapper;
}

void ftc_gpu_ctx_free(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return;

    if (wrapper->type == FTC_GPU_CUDA) {
        ftc_gpu_ctx_free_cuda(wrapper->backend_ctx);
    } else {
        ftc_gpu_ctx_free_opencl(wrapper->backend_ctx);
    }

    free(wrapper);
}

const ftc_gpu_device_t* ftc_gpu_ctx_device(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    return wrapper ? &wrapper->device : NULL;
}

bool ftc_gpu_set_work(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32])
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return false;

    if (wrapper->type == FTC_GPU_CUDA) {
        return ftc_gpu_set_work_cuda(wrapper->backend_ctx, header, target);
    } else {
        return ftc_gpu_set_work_opencl(wrapper->backend_ctx, header, target);
    }
}

/* Launch kernel asynchronously (non-blocking) */
void ftc_gpu_launch(ftc_gpu_ctx_t* ctx, uint32_t nonce_start)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return;

    if (wrapper->type == FTC_GPU_CUDA) {
        ftc_gpu_launch_cuda(wrapper->backend_ctx, nonce_start);
    } else if (wrapper->type == FTC_GPU_OPENCL) {
        /* OpenCL: store nonce for sync call (emulated async) */
        wrapper->pending_nonce = nonce_start;
    }
}

/* Synchronize and get results */
ftc_gpu_result_t ftc_gpu_sync(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    ftc_gpu_result_t result = {0};
    if (!wrapper) return result;

    if (wrapper->type == FTC_GPU_CUDA) {
        return ftc_gpu_sync_cuda(wrapper->backend_ctx);
    } else if (wrapper->type == FTC_GPU_OPENCL) {
        /* OpenCL: run synchronous mining with stored nonce */
        return ftc_gpu_mine_opencl(wrapper->backend_ctx, wrapper->pending_nonce);
    }
    return result;
}

/* Synchronous mining (legacy) */
ftc_gpu_result_t ftc_gpu_mine(ftc_gpu_ctx_t* ctx, uint32_t nonce_start)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    ftc_gpu_result_t result = {0};
    if (!wrapper) return result;

    if (wrapper->type == FTC_GPU_CUDA) {
        return ftc_gpu_mine_cuda(wrapper->backend_ctx, nonce_start);
    } else {
        return ftc_gpu_mine_opencl(wrapper->backend_ctx, nonce_start);
    }
}

double ftc_gpu_get_hashrate(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return 0;

    if (wrapper->type == FTC_GPU_CUDA) {
        return ftc_gpu_get_hashrate_cuda(wrapper->backend_ctx);
    } else {
        return ftc_gpu_get_hashrate_opencl(wrapper->backend_ctx);
    }
}

uint64_t ftc_gpu_get_total_hashes(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return 0;

    if (wrapper->type == FTC_GPU_CUDA) {
        return ftc_gpu_get_total_hashes_cuda(wrapper->backend_ctx);
    } else {
        return ftc_gpu_get_total_hashes_opencl(wrapper->backend_ctx);
    }
}

void ftc_gpu_update_stats(ftc_gpu_ctx_t* ctx)
{
    ftc_gpu_ctx_wrapper_t* wrapper = (ftc_gpu_ctx_wrapper_t*)ctx;
    if (!wrapper) return;

    if (wrapper->type == FTC_GPU_CUDA) {
        ftc_gpu_update_stats_cuda(wrapper->backend_ctx);
    } else {
        ftc_gpu_update_stats_opencl(wrapper->backend_ctx);
    }
}

/*==============================================================================
 * MULTI-GPU FARM
 *============================================================================*/

struct ftc_gpu_farm {
    ftc_gpu_ctx_t*  contexts[FTC_GPU_MAX_DEVICES];
    int             device_count;
    uint32_t        batch_size;
    uint32_t        nonce_offset;

    /* Work data */
    uint8_t         header[80];
    uint8_t         target[32];

    /* Stats */
    double          total_hashrate;
    uint64_t        total_hashes;
};

ftc_gpu_farm_t* ftc_gpu_farm_new(uint32_t device_mask, uint32_t batch_size)
{
    if (g_device_count == 0) return NULL;

    ftc_gpu_farm_t* farm = (ftc_gpu_farm_t*)calloc(1, sizeof(ftc_gpu_farm_t));
    if (!farm) return NULL;

    farm->batch_size = (batch_size > 0) ? batch_size : FTC_GPU_BATCH_SIZE;
    farm->nonce_offset = 0;

    /* Initialize selected devices */
    for (int i = 0; i < g_device_count; i++) {
        if (device_mask == 0 || (device_mask & (1 << i))) {
            farm->contexts[farm->device_count] = ftc_gpu_ctx_new(i, farm->batch_size);
            if (farm->contexts[farm->device_count]) {
                farm->device_count++;
            }
        }
    }

    if (farm->device_count == 0) {
        free(farm);
        return NULL;
    }

    return farm;
}

void ftc_gpu_farm_free(ftc_gpu_farm_t* farm)
{
    if (!farm) return;

    for (int i = 0; i < farm->device_count; i++) {
        if (farm->contexts[i]) {
            ftc_gpu_ctx_free(farm->contexts[i]);
        }
    }

    free(farm);
}

bool ftc_gpu_farm_set_work(ftc_gpu_farm_t* farm, const uint8_t header[80], const uint8_t target[32])
{
    if (!farm) return false;

    memcpy(farm->header, header, 80);
    memcpy(farm->target, target, 32);
    farm->nonce_offset = 0;

    for (int i = 0; i < farm->device_count; i++) {
        if (!ftc_gpu_set_work(farm->contexts[i], header, target)) {
            return false;
        }
    }

    return true;
}

ftc_gpu_result_t ftc_gpu_farm_mine(ftc_gpu_farm_t* farm)
{
    ftc_gpu_result_t result = {0};
    if (!farm || farm->device_count == 0) return result;

    /* PHASE 1: Launch all kernels in parallel (non-blocking) */
    for (int i = 0; i < farm->device_count; i++) {
        uint32_t nonce_start = farm->nonce_offset + i * farm->batch_size;
        ftc_gpu_launch(farm->contexts[i], nonce_start);
    }

    /* PHASE 2: Synchronize all GPUs and collect results */
    for (int i = 0; i < farm->device_count; i++) {
        ftc_gpu_result_t dev_result = ftc_gpu_sync(farm->contexts[i]);

        result.hashes += dev_result.hashes;
        if (dev_result.elapsed_ms > result.elapsed_ms) {
            result.elapsed_ms = dev_result.elapsed_ms;  /* Take max time */
        }

        if (dev_result.found && !result.found) {
            result.found = true;
            result.nonce = dev_result.nonce;
            memcpy(result.hash, dev_result.hash, 32);
            /* Don't break - need to sync all GPUs to get accurate hashrates */
        }
    }

    /* Advance nonce offset for next iteration */
    farm->nonce_offset += farm->device_count * farm->batch_size;

    /* Update stats */
    farm->total_hashes += result.hashes;

    return result;
}

double ftc_gpu_farm_get_hashrate(ftc_gpu_farm_t* farm)
{
    if (!farm) return 0;

    double total = 0;
    for (int i = 0; i < farm->device_count; i++) {
        total += ftc_gpu_get_hashrate(farm->contexts[i]);
    }
    return total;
}

int ftc_gpu_farm_device_count(ftc_gpu_farm_t* farm)
{
    return farm ? farm->device_count : 0;
}

double ftc_gpu_farm_get_device_hashrate(ftc_gpu_farm_t* farm, int device_idx)
{
    if (!farm || device_idx < 0 || device_idx >= farm->device_count) return 0;
    return ftc_gpu_get_hashrate(farm->contexts[device_idx]);
}

const ftc_gpu_device_t* ftc_gpu_farm_get_device(ftc_gpu_farm_t* farm, int device_idx)
{
    if (!farm || device_idx < 0 || device_idx >= farm->device_count) return NULL;
    return ftc_gpu_ctx_device(farm->contexts[device_idx]);
}
