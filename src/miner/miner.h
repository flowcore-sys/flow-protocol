/**
 * FTC CPU Miner
 *
 * Multi-threaded proof-of-work mining
 */

#ifndef FTC_MINER_H
#define FTC_MINER_H

#include "../include/ftc.h"
#include "../core/block.h"
#include "../core/tx.h"
#include "../crypto/keys.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_MINER_DEFAULT_THREADS   4
#define FTC_MINER_BATCH_SIZE        65536  /* Nonces per batch */

/*==============================================================================
 * MINER STATE
 *============================================================================*/

typedef enum {
    FTC_MINER_STOPPED = 0,
    FTC_MINER_STARTING,
    FTC_MINER_RUNNING,
    FTC_MINER_STOPPING,
} ftc_miner_state_t;

/*==============================================================================
 * MINER STATS
 *============================================================================*/

typedef struct {
    uint64_t        hashes_total;
    uint64_t        hashes_per_sec;
    uint64_t        blocks_found;
    uint64_t        blocks_accepted;
    double          difficulty;
    int64_t         start_time;
    int64_t         last_block_time;
} ftc_miner_stats_t;

/*==============================================================================
 * MINER CALLBACKS
 *============================================================================*/

typedef struct ftc_miner ftc_miner_t;

typedef struct {
    /* Called when a valid block is found */
    bool (*on_block_found)(ftc_miner_t* miner, ftc_block_t* block, void* ctx);

    /* Called to get new block template */
    ftc_block_t* (*get_block_template)(ftc_miner_t* miner, void* ctx);

    /* Called periodically with stats */
    void (*on_stats_update)(ftc_miner_t* miner, const ftc_miner_stats_t* stats, void* ctx);

} ftc_miner_callbacks_t;

/*==============================================================================
 * MINER STRUCTURE
 *============================================================================*/

struct ftc_miner {
    /* State */
    ftc_miner_state_t   state;
    int                 num_threads;

    /* Mining address */
    ftc_address_t       miner_address;

    /* Current block template */
    ftc_block_t*        block_template;
    uint8_t             header_data[80];
    ftc_hash256_t       target;

    /* Thread synchronization */
    volatile bool       should_stop;
    volatile bool       new_block_found;
    volatile uint64_t   total_hashes;

#ifdef _WIN32
    void*               threads[64];
#else
    unsigned long       threads[64];
#endif

    /* Stats */
    ftc_miner_stats_t   stats;
    int64_t             last_stats_time;

    /* Callbacks */
    ftc_miner_callbacks_t* callbacks;
    void*               user_data;
};

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create miner
 */
ftc_miner_t* ftc_miner_new(int num_threads);

/**
 * Free miner
 */
void ftc_miner_free(ftc_miner_t* miner);

/**
 * Set miner address
 */
void ftc_miner_set_address(ftc_miner_t* miner, const ftc_address_t address);

/**
 * Set miner address from string
 */
bool ftc_miner_set_address_str(ftc_miner_t* miner, const char* addr_str);

/**
 * Set callbacks
 */
void ftc_miner_set_callbacks(ftc_miner_t* miner, ftc_miner_callbacks_t* callbacks, void* user_data);

/**
 * Start mining
 */
bool ftc_miner_start(ftc_miner_t* miner);

/**
 * Stop mining
 */
void ftc_miner_stop(ftc_miner_t* miner);

/**
 * Check if mining
 */
bool ftc_miner_is_running(ftc_miner_t* miner);

/**
 * Update block template
 */
void ftc_miner_update_template(ftc_miner_t* miner, ftc_block_t* block);

/**
 * Get mining stats
 */
void ftc_miner_get_stats(ftc_miner_t* miner, ftc_miner_stats_t* stats);

/**
 * Mine a single block (blocking)
 * Returns true if valid block found
 */
bool ftc_miner_mine_block(ftc_block_t* block, uint64_t max_nonce);

/**
 * Check if hash meets target
 */
bool ftc_miner_check_hash(const ftc_hash256_t hash, const ftc_hash256_t target);

#ifdef __cplusplus
}
#endif

#endif /* FTC_MINER_H */
