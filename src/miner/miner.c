/**
 * FTC CPU Miner Implementation
 */

#include "miner.h"
#include "../crypto/keccak256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

/*==============================================================================
 * UTILITIES
 *============================================================================*/

static int64_t get_time_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (int64_t)((time - 116444736000000000ULL) / 10000);
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

bool ftc_miner_check_hash(const ftc_hash256_t hash, const ftc_hash256_t target)
{
    /* Compare hash to target (big-endian comparison) */
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;  /* Equal */
}

/*==============================================================================
 * THREAD WORKER
 *============================================================================*/

typedef struct {
    ftc_miner_t*    miner;
    int             thread_id;
    uint32_t        nonce_start;
    uint32_t        nonce_range;
} miner_thread_ctx_t;

static void mine_range(ftc_miner_t* miner, uint32_t nonce_start, uint32_t nonce_range)
{
    uint8_t header[80];
    memcpy(header, miner->header_data, 80);

    ftc_hash256_t hash;

    for (uint32_t i = 0; i < nonce_range && !miner->should_stop && !miner->new_block_found; i++) {
        uint32_t nonce = nonce_start + i;

        /* Update nonce in header (bytes 76-79) */
        header[76] = (uint8_t)(nonce);
        header[77] = (uint8_t)(nonce >> 8);
        header[78] = (uint8_t)(nonce >> 16);
        header[79] = (uint8_t)(nonce >> 24);

        /* Double Keccak-256 */
        ftc_keccak256_double(header, 80, hash);

        /* Check if valid */
        if (ftc_miner_check_hash(hash, miner->target)) {
            miner->block_template->header.nonce = nonce;
            miner->new_block_found = true;
            return;
        }
    }

    /* Update hash count */
#ifdef _WIN32
    InterlockedAdd64((volatile LONG64*)&miner->total_hashes, nonce_range);
#else
    __sync_fetch_and_add(&miner->total_hashes, nonce_range);
#endif
}

#ifdef _WIN32
static unsigned __stdcall miner_thread(void* arg)
#else
static void* miner_thread(void* arg)
#endif
{
    miner_thread_ctx_t* ctx = (miner_thread_ctx_t*)arg;
    ftc_miner_t* miner = ctx->miner;
    int thread_id = ctx->thread_id;
    free(ctx);

    uint32_t nonce_base = thread_id * (0xFFFFFFFF / miner->num_threads);

    while (!miner->should_stop) {
        if (miner->block_template && !miner->new_block_found) {
            mine_range(miner, nonce_base, FTC_MINER_BATCH_SIZE);
            nonce_base += FTC_MINER_BATCH_SIZE;

            /* Wrap around */
            if (nonce_base < FTC_MINER_BATCH_SIZE) {
                nonce_base = thread_id * (0xFFFFFFFF / miner->num_threads);
            }
        } else {
            /* Wait for new work */
#ifdef _WIN32
            Sleep(10);
#else
            usleep(10000);
#endif
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

ftc_miner_t* ftc_miner_new(int num_threads)
{
    ftc_miner_t* miner = (ftc_miner_t*)calloc(1, sizeof(ftc_miner_t));
    if (!miner) return NULL;

    miner->num_threads = num_threads > 0 ? num_threads : FTC_MINER_DEFAULT_THREADS;
    if (miner->num_threads > 64) miner->num_threads = 64;

    miner->state = FTC_MINER_STOPPED;
    return miner;
}

void ftc_miner_free(ftc_miner_t* miner)
{
    if (!miner) return;

    ftc_miner_stop(miner);

    if (miner->block_template) {
        ftc_block_free(miner->block_template);
    }

    free(miner);
}

void ftc_miner_set_address(ftc_miner_t* miner, const ftc_address_t address)
{
    memcpy(miner->miner_address, address, 20);
}

bool ftc_miner_set_address_str(ftc_miner_t* miner, const char* addr_str)
{
    return ftc_address_decode(addr_str, miner->miner_address, NULL);
}

void ftc_miner_set_callbacks(ftc_miner_t* miner, ftc_miner_callbacks_t* callbacks, void* user_data)
{
    miner->callbacks = callbacks;
    miner->user_data = user_data;
}

bool ftc_miner_start(ftc_miner_t* miner)
{
    if (miner->state == FTC_MINER_RUNNING) return true;

    miner->should_stop = false;
    miner->new_block_found = false;
    miner->total_hashes = 0;
    miner->state = FTC_MINER_STARTING;

    miner->stats.start_time = get_time_ms();
    miner->last_stats_time = miner->stats.start_time;

    /* Start worker threads */
    for (int i = 0; i < miner->num_threads; i++) {
        miner_thread_ctx_t* ctx = (miner_thread_ctx_t*)malloc(sizeof(miner_thread_ctx_t));
        ctx->miner = miner;
        ctx->thread_id = i;

#ifdef _WIN32
        miner->threads[i] = (HANDLE)_beginthreadex(NULL, 0, miner_thread, ctx, 0, NULL);
#else
        pthread_create((pthread_t*)&miner->threads[i], NULL, miner_thread, ctx);
#endif
    }

    miner->state = FTC_MINER_RUNNING;
    printf("[MINER] Started with %d threads\n", miner->num_threads);
    return true;
}

void ftc_miner_stop(ftc_miner_t* miner)
{
    if (miner->state != FTC_MINER_RUNNING) return;

    miner->state = FTC_MINER_STOPPING;
    miner->should_stop = true;

    /* Wait for threads */
    for (int i = 0; i < miner->num_threads; i++) {
#ifdef _WIN32
        if (miner->threads[i]) {
            WaitForSingleObject(miner->threads[i], INFINITE);
            CloseHandle(miner->threads[i]);
            miner->threads[i] = NULL;
        }
#else
        if (miner->threads[i]) {
            pthread_join((pthread_t)miner->threads[i], NULL);
            miner->threads[i] = 0;
        }
#endif
    }

    miner->state = FTC_MINER_STOPPED;
    printf("[MINER] Stopped\n");
}

bool ftc_miner_is_running(ftc_miner_t* miner)
{
    return miner->state == FTC_MINER_RUNNING;
}

void ftc_miner_update_template(ftc_miner_t* miner, ftc_block_t* block)
{
    if (miner->block_template) {
        ftc_block_free(miner->block_template);
    }

    miner->block_template = block;
    miner->new_block_found = false;

    /* Prepare header data */
    ftc_block_header_serialize(&block->header, miner->header_data);

    /* Get target from bits */
    ftc_bits_to_target(block->header.bits, miner->target);

    miner->stats.difficulty = ftc_bits_to_difficulty(block->header.bits);
}

void ftc_miner_get_stats(ftc_miner_t* miner, ftc_miner_stats_t* stats)
{
    int64_t now = get_time_ms();
    int64_t elapsed = now - miner->last_stats_time;

    if (elapsed > 0) {
        stats->hashes_per_sec = (miner->total_hashes * 1000) / (now - miner->stats.start_time);
    } else {
        stats->hashes_per_sec = 0;
    }

    stats->hashes_total = miner->total_hashes;
    stats->blocks_found = miner->stats.blocks_found;
    stats->blocks_accepted = miner->stats.blocks_accepted;
    stats->difficulty = miner->stats.difficulty;
    stats->start_time = miner->stats.start_time;
    stats->last_block_time = miner->stats.last_block_time;
}

bool ftc_miner_mine_block(ftc_block_t* block, uint64_t max_nonce)
{
    uint8_t header[80];
    ftc_block_header_serialize(&block->header, header);

    ftc_hash256_t target;
    ftc_bits_to_target(block->header.bits, target);

    ftc_hash256_t hash;

    for (uint64_t nonce = 0; nonce < max_nonce; nonce++) {
        /* Update nonce */
        header[76] = (uint8_t)(nonce);
        header[77] = (uint8_t)(nonce >> 8);
        header[78] = (uint8_t)(nonce >> 16);
        header[79] = (uint8_t)(nonce >> 24);

        /* Hash */
        ftc_keccak256_double(header, 80, hash);

        /* Check */
        if (ftc_miner_check_hash(hash, target)) {
            block->header.nonce = (uint32_t)nonce;
            return true;
        }

        /* Progress */
        if ((nonce & 0xFFFFF) == 0) {
            printf("\r[MINER] Nonce: %llu", (unsigned long long)nonce);
            fflush(stdout);
        }
    }

    return false;
}
