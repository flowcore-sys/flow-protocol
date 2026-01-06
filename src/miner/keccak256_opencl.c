/**
 * FTC OpenCL Keccak-256 Mining Implementation
 *
 * Host code for AMD/Intel GPU mining.
 * Loads and manages OpenCL kernels.
 */

#include "gpu_miner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define FTC_OPENCL_DLL "OpenCL.dll"
#else
#include <dlfcn.h>
#include <sys/time.h>
#define FTC_OPENCL_DLL "libOpenCL.so"
#endif

/* Only compile if OpenCL is available */
#ifdef FTC_HAS_OPENCL

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

/*==============================================================================
 * FORWARD DECLARATIONS
 *============================================================================*/

void ftc_gpu_ctx_free_opencl(ftc_gpu_ctx_t* ctx);

/*==============================================================================
 * EMBEDDED KERNEL SOURCE
 *============================================================================*/

static const char* g_kernel_source =
#include "keccak256_cl_embedded.h"
;

/*==============================================================================
 * OPENCL CONTEXT STRUCTURE
 *============================================================================*/

typedef struct ftc_gpu_ctx_opencl {
    int             device_id;
    ftc_gpu_device_t device;
    uint32_t        batch_size;

    /* OpenCL objects */
    cl_platform_id  platform;
    cl_device_id    cl_device;
    cl_context      context;
    cl_command_queue queue;
    cl_program      program;
    cl_kernel       kernel;

    /* Device memory */
    cl_mem          d_header;
    cl_mem          d_target;
    cl_mem          d_result_nonce;
    cl_mem          d_result_hash;
    cl_mem          d_found;

    /* Host memory */
    uint8_t         h_header[80];
    uint8_t         h_target[32];

    /* Statistics */
    uint64_t        total_hashes;
    double          last_hashrate;
    double          last_elapsed;
} ftc_gpu_ctx_opencl_t;

/*==============================================================================
 * GLOBAL STATE
 *============================================================================*/

static ftc_gpu_device_t g_opencl_devices[FTC_GPU_MAX_DEVICES];
static cl_device_id g_cl_devices[FTC_GPU_MAX_DEVICES];
static cl_platform_id g_cl_platforms[FTC_GPU_MAX_DEVICES];
static int g_opencl_device_count = 0;
static bool g_opencl_initialized = false;

/*==============================================================================
 * TIMING UTILITIES
 *============================================================================*/

static double get_time_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

/*==============================================================================
 * DEVICE ENUMERATION (OpenCL)
 *============================================================================*/

int ftc_gpu_init_opencl(void)
{
    if (g_opencl_initialized) return g_opencl_device_count;

    cl_uint num_platforms = 0;
    cl_platform_id platforms[8];

    if (clGetPlatformIDs(8, platforms, &num_platforms) != CL_SUCCESS) {
        g_opencl_initialized = true;
        return 0;
    }

    for (cl_uint p = 0; p < num_platforms && g_opencl_device_count < FTC_GPU_MAX_DEVICES; p++) {
        cl_uint num_devices = 0;
        cl_device_id devices[8];

        if (clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 8, devices, &num_devices) != CL_SUCCESS) {
            continue;
        }

        for (cl_uint d = 0; d < num_devices && g_opencl_device_count < FTC_GPU_MAX_DEVICES; d++) {
            ftc_gpu_device_t* dev = &g_opencl_devices[g_opencl_device_count];

            dev->id = g_opencl_device_count;
            dev->type = FTC_GPU_OPENCL;

            clGetDeviceInfo(devices[d], CL_DEVICE_NAME, sizeof(dev->name), dev->name, NULL);
            clGetDeviceInfo(devices[d], CL_DEVICE_VENDOR, sizeof(dev->vendor), dev->vendor, NULL);

            cl_ulong mem_size = 0;
            clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem_size), &mem_size, NULL);
            dev->memory_total = mem_size;
            dev->memory_free = mem_size;

            cl_uint compute_units = 0;
            clGetDeviceInfo(devices[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(compute_units), &compute_units, NULL);
            dev->compute_units = compute_units;

            cl_uint clock_freq = 0;
            clGetDeviceInfo(devices[d], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(clock_freq), &clock_freq, NULL);
            dev->clock_mhz = clock_freq;

            dev->pci_bus = 0;
            dev->pci_device = 0;
            dev->power_limit = 0;
            dev->temperature = 0;
            dev->available = true;

            g_cl_devices[g_opencl_device_count] = devices[d];
            g_cl_platforms[g_opencl_device_count] = platforms[p];
            g_opencl_device_count++;
        }
    }

    g_opencl_initialized = true;
    return g_opencl_device_count;
}

void ftc_gpu_shutdown_opencl(void)
{
    g_opencl_initialized = false;
    g_opencl_device_count = 0;
}

const ftc_gpu_device_t* ftc_gpu_get_opencl_device(int idx)
{
    if (idx < 0 || idx >= g_opencl_device_count) return NULL;
    return &g_opencl_devices[idx];
}

int ftc_gpu_opencl_count(void)
{
    return g_opencl_device_count;
}

/*==============================================================================
 * KERNEL LOADING
 *============================================================================*/

static bool load_kernel_from_file(const char* filename, char** source, size_t* length)
{
    FILE* fp = fopen(filename, "rb");
    if (!fp) return false;

    fseek(fp, 0, SEEK_END);
    *length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *source = (char*)malloc(*length + 1);
    if (!*source) {
        fclose(fp);
        return false;
    }

    fread(*source, 1, *length, fp);
    (*source)[*length] = '\0';
    fclose(fp);
    return true;
}

/*==============================================================================
 * MINING CONTEXT (OpenCL)
 *============================================================================*/

ftc_gpu_ctx_t* ftc_gpu_ctx_new_opencl(int device_id, uint32_t batch_size)
{
    if (device_id < 0 || device_id >= g_opencl_device_count) return NULL;

    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)calloc(1, sizeof(ftc_gpu_ctx_opencl_t));
    if (!ctx) return NULL;

    ctx->device_id = device_id;
    ctx->device = g_opencl_devices[device_id];
    ctx->batch_size = batch_size > 0 ? batch_size : FTC_GPU_BATCH_SIZE;
    ctx->platform = g_cl_platforms[device_id];
    ctx->cl_device = g_cl_devices[device_id];

    cl_int err;

    /* Create context */
    ctx->context = clCreateContext(NULL, 1, &ctx->cl_device, NULL, NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: Failed to create context (error %d)\n", err);
        free(ctx);
        return NULL;
    }

    /* Create command queue */
    ctx->queue = clCreateCommandQueue(ctx->context, ctx->cl_device, 0, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: Failed to create command queue (error %d)\n", err);
        clReleaseContext(ctx->context);
        free(ctx);
        return NULL;
    }

    /* Try to load kernel from file first */
    char* kernel_source = NULL;
    size_t kernel_length = 0;
    bool from_file = load_kernel_from_file("keccak256.cl", &kernel_source, &kernel_length);

    if (!from_file) {
        /* Use embedded kernel source */
        kernel_source = (char*)g_kernel_source;
        kernel_length = strlen(g_kernel_source);
    }

    /* Build program */
    ctx->program = clCreateProgramWithSource(ctx->context, 1, (const char**)&kernel_source, &kernel_length, &err);
    if (from_file) free(kernel_source);

    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: Failed to create program (error %d)\n", err);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->context);
        free(ctx);
        return NULL;
    }

    err = clBuildProgram(ctx->program, 1, &ctx->cl_device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        char build_log[4096];
        clGetProgramBuildInfo(ctx->program, ctx->cl_device, CL_PROGRAM_BUILD_LOG, sizeof(build_log), build_log, NULL);
        fprintf(stderr, "OpenCL: Build failed:\n%s\n", build_log);
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->context);
        free(ctx);
        return NULL;
    }

    /* Create kernel */
    ctx->kernel = clCreateKernel(ctx->program, "keccak256_mine", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: Failed to create kernel (error %d)\n", err);
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->context);
        free(ctx);
        return NULL;
    }

    /* Allocate device memory */
    ctx->d_header = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY, 80, NULL, &err);
    ctx->d_target = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY, 32, NULL, &err);
    ctx->d_result_nonce = clCreateBuffer(ctx->context, CL_MEM_WRITE_ONLY, sizeof(uint32_t), NULL, &err);
    ctx->d_result_hash = clCreateBuffer(ctx->context, CL_MEM_WRITE_ONLY, 32, NULL, &err);
    ctx->d_found = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE, sizeof(uint32_t), NULL, &err);

    if (!ctx->d_header || !ctx->d_target || !ctx->d_result_nonce || !ctx->d_result_hash || !ctx->d_found) {
        fprintf(stderr, "OpenCL: Failed to allocate device memory\n");
        ftc_gpu_ctx_free_opencl((ftc_gpu_ctx_t*)ctx);
        return NULL;
    }

    return (ftc_gpu_ctx_t*)ctx;
}

void ftc_gpu_ctx_free_opencl(ftc_gpu_ctx_t* ctx_raw)
{
    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)ctx_raw;
    if (!ctx) return;

    if (ctx->d_header) clReleaseMemObject(ctx->d_header);
    if (ctx->d_target) clReleaseMemObject(ctx->d_target);
    if (ctx->d_result_nonce) clReleaseMemObject(ctx->d_result_nonce);
    if (ctx->d_result_hash) clReleaseMemObject(ctx->d_result_hash);
    if (ctx->d_found) clReleaseMemObject(ctx->d_found);

    if (ctx->kernel) clReleaseKernel(ctx->kernel);
    if (ctx->program) clReleaseProgram(ctx->program);
    if (ctx->queue) clReleaseCommandQueue(ctx->queue);
    if (ctx->context) clReleaseContext(ctx->context);

    free(ctx);
}

/*==============================================================================
 * MINING OPERATIONS (OpenCL)
 *============================================================================*/

bool ftc_gpu_set_work_opencl(ftc_gpu_ctx_t* ctx_raw, const uint8_t header[80], const uint8_t target[32])
{
    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)ctx_raw;
    if (!ctx) return false;

    memcpy(ctx->h_header, header, 80);
    memcpy(ctx->h_target, target, 32);

    cl_int err;
    err = clEnqueueWriteBuffer(ctx->queue, ctx->d_header, CL_FALSE, 0, 80, header, 0, NULL, NULL);
    if (err != CL_SUCCESS) return false;

    err = clEnqueueWriteBuffer(ctx->queue, ctx->d_target, CL_FALSE, 0, 32, target, 0, NULL, NULL);
    if (err != CL_SUCCESS) return false;

    clFinish(ctx->queue);
    return true;
}

ftc_gpu_result_t ftc_gpu_mine_opencl(ftc_gpu_ctx_t* ctx_raw, uint32_t nonce_start)
{
    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)ctx_raw;
    ftc_gpu_result_t result = {0};
    if (!ctx) return result;

    cl_int err;

    /* Reset found flag */
    uint32_t zero = 0;
    clEnqueueWriteBuffer(ctx->queue, ctx->d_found, CL_FALSE, 0, sizeof(uint32_t), &zero, 0, NULL, NULL);

    /* Set kernel arguments */
    clSetKernelArg(ctx->kernel, 0, sizeof(cl_mem), &ctx->d_header);
    clSetKernelArg(ctx->kernel, 1, sizeof(cl_mem), &ctx->d_target);
    clSetKernelArg(ctx->kernel, 2, sizeof(uint32_t), &nonce_start);
    clSetKernelArg(ctx->kernel, 3, sizeof(cl_mem), &ctx->d_result_nonce);
    clSetKernelArg(ctx->kernel, 4, sizeof(cl_mem), &ctx->d_result_hash);
    clSetKernelArg(ctx->kernel, 5, sizeof(cl_mem), &ctx->d_found);

    /* Launch kernel */
    size_t global_size = ctx->batch_size;
    size_t local_size = FTC_GPU_WORK_SIZE;

    /* Round up to multiple of local_size */
    global_size = ((global_size + local_size - 1) / local_size) * local_size;

    double start_time = get_time_ms();

    err = clEnqueueNDRangeKernel(ctx->queue, ctx->kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: Kernel launch failed (error %d)\n", err);
        return result;
    }

    clFinish(ctx->queue);

    double elapsed_ms = get_time_ms() - start_time;

    /* Check result */
    uint32_t found = 0;
    clEnqueueReadBuffer(ctx->queue, ctx->d_found, CL_TRUE, 0, sizeof(uint32_t), &found, 0, NULL, NULL);

    result.hashes = ctx->batch_size;
    result.elapsed_ms = elapsed_ms;

    if (found) {
        result.found = true;
        clEnqueueReadBuffer(ctx->queue, ctx->d_result_nonce, CL_TRUE, 0, sizeof(uint32_t), &result.nonce, 0, NULL, NULL);
        clEnqueueReadBuffer(ctx->queue, ctx->d_result_hash, CL_TRUE, 0, 32, result.hash, 0, NULL, NULL);
    }

    /* Update stats */
    ctx->total_hashes += ctx->batch_size;
    ctx->last_elapsed = elapsed_ms;
    if (elapsed_ms > 0) {
        ctx->last_hashrate = (double)ctx->batch_size * 1000.0 / elapsed_ms;
    }

    return result;
}

double ftc_gpu_get_hashrate_opencl(ftc_gpu_ctx_t* ctx_raw)
{
    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)ctx_raw;
    return ctx ? ctx->last_hashrate : 0;
}

uint64_t ftc_gpu_get_total_hashes_opencl(ftc_gpu_ctx_t* ctx_raw)
{
    ftc_gpu_ctx_opencl_t* ctx = (ftc_gpu_ctx_opencl_t*)ctx_raw;
    return ctx ? ctx->total_hashes : 0;
}

void ftc_gpu_update_stats_opencl(ftc_gpu_ctx_t* ctx)
{
    /* AMD ADL would be used here for temperature/power monitoring */
    (void)ctx;
}

#else /* FTC_HAS_OPENCL not defined */

/* Stub functions when OpenCL is not available */
int ftc_gpu_init_opencl(void) { return 0; }
void ftc_gpu_shutdown_opencl(void) {}
const ftc_gpu_device_t* ftc_gpu_get_opencl_device(int idx) { (void)idx; return NULL; }
int ftc_gpu_opencl_count(void) { return 0; }
ftc_gpu_ctx_t* ftc_gpu_ctx_new_opencl(int device_id, uint32_t batch_size) { (void)device_id; (void)batch_size; return NULL; }
void ftc_gpu_ctx_free_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; }
bool ftc_gpu_set_work_opencl(ftc_gpu_ctx_t* ctx, const uint8_t header[80], const uint8_t target[32]) { (void)ctx; (void)header; (void)target; return false; }
ftc_gpu_result_t ftc_gpu_mine_opencl(ftc_gpu_ctx_t* ctx, uint32_t nonce_start) { (void)ctx; (void)nonce_start; ftc_gpu_result_t r = {0}; return r; }
double ftc_gpu_get_hashrate_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
uint64_t ftc_gpu_get_total_hashes_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; return 0; }
void ftc_gpu_update_stats_opencl(ftc_gpu_ctx_t* ctx) { (void)ctx; }

#endif /* FTC_HAS_OPENCL */
