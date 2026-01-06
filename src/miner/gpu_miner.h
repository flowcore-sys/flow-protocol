/**
 * FTC GPU Mining Abstraction Layer
 *
 * Unified interface for NVIDIA (CUDA) and AMD (OpenCL) mining.
 * Supports multi-GPU configurations for mining farms.
 */

#ifndef FTC_GPU_MINER_H
#define FTC_GPU_MINER_H

#include "../include/ftc.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_GPU_MAX_DEVICES     16
#define FTC_GPU_BATCH_SIZE      (1 << 24)   /* 16M hashes per batch */
#define FTC_GPU_WORK_SIZE       256         /* Work group size */

/*==============================================================================
 * GPU DEVICE TYPES
 *============================================================================*/

typedef enum {
    FTC_GPU_NONE = 0,
    FTC_GPU_CUDA,       /* NVIDIA CUDA */
    FTC_GPU_OPENCL      /* AMD/Intel OpenCL */
} ftc_gpu_type_t;

/*==============================================================================
 * GPU DEVICE INFO
 *============================================================================*/

typedef struct {
    int             id;                 /* Device index */
    ftc_gpu_type_t  type;              /* CUDA or OpenCL */
    char            name[128];         /* Device name */
    char            vendor[64];        /* Vendor name */
    uint64_t        memory_total;      /* Total memory in bytes */
    uint64_t        memory_free;       /* Free memory in bytes */
    int             compute_units;     /* SM count (CUDA) / CU count (OpenCL) */
    int             clock_mhz;         /* Core clock */
    int             pci_bus;           /* PCI bus ID */
    int             pci_device;        /* PCI device ID */
    double          power_limit;       /* Power limit in watts */
    double          temperature;       /* Current temperature */
    bool            available;         /* Device ready for mining */
} ftc_gpu_device_t;

/*==============================================================================
 * GPU MINING CONTEXT
 *============================================================================*/

typedef struct ftc_gpu_ctx ftc_gpu_ctx_t;

/*==============================================================================
 * GPU MINING RESULT
 *============================================================================*/

typedef struct {
    bool        found;          /* Valid nonce found */
    uint32_t    nonce;          /* Winning nonce */
    uint8_t     hash[32];       /* Resulting hash */
    uint64_t    hashes;         /* Number of hashes computed */
    double      elapsed_ms;     /* Time elapsed */
} ftc_gpu_result_t;

/*==============================================================================
 * GPU WORK PACKAGE
 *============================================================================*/

typedef struct {
    uint8_t     header[80];     /* Block header (nonce at bytes 76-79) */
    uint8_t     target[32];     /* Target hash */
    uint32_t    nonce_start;    /* Starting nonce */
    uint32_t    nonce_count;    /* Number of nonces to try */
} ftc_gpu_work_t;

/*==============================================================================
 * DEVICE ENUMERATION
 *============================================================================*/

/**
 * Initialize GPU subsystem
 * Detects available GPUs (CUDA and OpenCL)
 * Returns number of available devices, or -1 on error
 */
int ftc_gpu_init(void);

/**
 * Shutdown GPU subsystem
 */
void ftc_gpu_shutdown(void);

/**
 * Get number of available GPU devices
 */
int ftc_gpu_device_count(void);

/**
 * Get device information
 * Returns NULL if device_id is invalid
 */
const ftc_gpu_device_t* ftc_gpu_get_device(int device_id);

/**
 * Print device info to stdout
 */
void ftc_gpu_print_devices(void);

/*==============================================================================
 * MINING CONTEXT
 *============================================================================*/

/**
 * Create mining context for a specific device
 * batch_size: number of hashes per mining iteration (0 = auto)
 */
ftc_gpu_ctx_t* ftc_gpu_ctx_new(int device_id, uint32_t batch_size);

/**
 * Free mining context
 */
void ftc_gpu_ctx_free(ftc_gpu_ctx_t* ctx);

/**
 * Get device associated with context
 */
const ftc_gpu_device_t* ftc_gpu_ctx_device(ftc_gpu_ctx_t* ctx);

/*==============================================================================
 * MINING OPERATIONS
 *============================================================================*/

/**
 * Set mining work
 * header: 80-byte block header
 * target: 32-byte target hash (hash must be < target)
 */
bool ftc_gpu_set_work(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32]);

/**
 * Run mining iteration
 * Tries nonces from nonce_start to nonce_start + batch_size
 * Returns result with found=true if valid nonce discovered
 */
ftc_gpu_result_t ftc_gpu_mine(ftc_gpu_ctx_t* ctx, uint32_t nonce_start);

/**
 * Get current hashrate (hashes per second)
 */
double ftc_gpu_get_hashrate(ftc_gpu_ctx_t* ctx);

/**
 * Get total hashes computed since context creation
 */
uint64_t ftc_gpu_get_total_hashes(ftc_gpu_ctx_t* ctx);

/**
 * Update device temperature and power stats
 */
void ftc_gpu_update_stats(ftc_gpu_ctx_t* ctx);

/*==============================================================================
 * MULTI-GPU MANAGER
 *============================================================================*/

typedef struct ftc_gpu_farm ftc_gpu_farm_t;

/**
 * Create multi-GPU farm
 * device_mask: bitmask of devices to use (0 = all available)
 */
ftc_gpu_farm_t* ftc_gpu_farm_new(uint32_t device_mask);

/**
 * Free farm
 */
void ftc_gpu_farm_free(ftc_gpu_farm_t* farm);

/**
 * Set work for all GPUs
 */
bool ftc_gpu_farm_set_work(ftc_gpu_farm_t* farm, const uint8_t header[80], const uint8_t target[32]);

/**
 * Mine on all GPUs
 * Returns result from first GPU to find valid nonce
 * nonce_offset: each GPU gets a different nonce range
 */
ftc_gpu_result_t ftc_gpu_farm_mine(ftc_gpu_farm_t* farm);

/**
 * Get combined hashrate from all GPUs
 */
double ftc_gpu_farm_get_hashrate(ftc_gpu_farm_t* farm);

/**
 * Get active GPU count in farm
 */
int ftc_gpu_farm_device_count(ftc_gpu_farm_t* farm);

/**
 * Get hashrate for a specific device in farm
 */
double ftc_gpu_farm_get_device_hashrate(ftc_gpu_farm_t* farm, int device_idx);

/**
 * Get device info for a specific device in farm
 */
const ftc_gpu_device_t* ftc_gpu_farm_get_device(ftc_gpu_farm_t* farm, int device_idx);

#ifdef __cplusplus
}
#endif

#endif /* FTC_GPU_MINER_H */
