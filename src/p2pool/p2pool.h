/**
 * FTC P2Pool - Decentralized Mining Pool
 *
 * No central pool operator - rewards go directly to miners
 * Based on sharechain concept from Bitcoin P2Pool
 */

#ifndef FTC_P2POOL_H
#define FTC_P2POOL_H

#include "../../include/ftc.h"
#include "../core/block.h"
#include "../core/tx.h"
#include "../core/consensus.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_P2POOL_VERSION          1
#define FTC_P2POOL_SHARE_WINDOW     100     /* PPLNS window - last N shares */
#define FTC_P2POOL_SHARE_TARGET     0x1f00ffff  /* Share difficulty (much lower than network) */
#define FTC_P2POOL_MAX_OUTPUTS      100     /* Max coinbase outputs per block */
#define FTC_P2POOL_MIN_PAYOUT       100000  /* 0.001 FTC minimum payout (in satoshis) */
#define FTC_P2POOL_SHARE_EXPIRY     3600    /* Shares expire after 1 hour */

/*==============================================================================
 * SHARE STRUCTURE
 *============================================================================*/

/**
 * A share represents proof of work done by a miner
 * Shares have lower difficulty than real blocks
 */
typedef struct ftc_share {
    /* Header */
    uint32_t        version;
    ftc_hash256_t   prev_share;     /* Previous share hash */
    ftc_hash256_t   block_hash;     /* Main chain block being worked on */
    uint32_t        block_height;   /* Main chain height */
    uint32_t        timestamp;
    uint32_t        bits;           /* Share difficulty */
    uint32_t        nonce;

    /* Miner info */
    char            miner_address[64];  /* Miner's payout address */
    uint64_t        work_done;          /* Estimated hashes (for weighted PPLNS) */

    /* Computed */
    ftc_hash256_t   hash;           /* This share's hash */
    bool            is_block;       /* True if this share also meets block difficulty */
} ftc_share_t;

/*==============================================================================
 * PPLNS TRACKER
 *============================================================================*/

/**
 * Tracks miner contributions in current PPLNS window
 */
typedef struct ftc_pplns_entry {
    char            address[64];
    uint64_t        shares;         /* Number of shares */
    uint64_t        work;           /* Total work done */
} ftc_pplns_entry_t;

/**
 * PPLNS state
 */
typedef struct ftc_pplns {
    ftc_share_t*    shares;         /* Circular buffer of recent shares */
    int             share_count;
    int             share_capacity;
    int             share_head;     /* Next write position */

    ftc_pplns_entry_t* miners;      /* Aggregated miner stats */
    int             miner_count;
    int             miner_capacity;

    uint64_t        total_work;     /* Total work in window */
} ftc_pplns_t;

/*==============================================================================
 * P2POOL CONTEXT
 *============================================================================*/

typedef struct ftc_p2pool {
    /* Configuration */
    uint32_t        share_target;   /* Target for shares */
    int             pplns_window;   /* Number of shares in PPLNS window */
    uint64_t        min_payout;     /* Minimum payout amount */

    /* State */
    ftc_pplns_t*    pplns;          /* PPLNS tracker */
    ftc_hash256_t   best_share;     /* Best share hash (tip of sharechain) */
    uint32_t        share_height;   /* Number of shares in chain */

    /* Stats */
    uint64_t        total_shares;
    uint64_t        blocks_found;
    time_t          start_time;

    /* Reference to node */
    void*           node;
} ftc_p2pool_t;

/*==============================================================================
 * FUNCTIONS
 *============================================================================*/

/**
 * Create P2Pool context
 */
ftc_p2pool_t* ftc_p2pool_new(void* node);

/**
 * Free P2Pool context
 */
void ftc_p2pool_free(ftc_p2pool_t* p2pool);

/**
 * Submit a share from a miner
 * Returns true if share is valid
 */
bool ftc_p2pool_submit_share(ftc_p2pool_t* p2pool,
                              const char* miner_address,
                              const uint8_t* block_header,
                              uint32_t nonce);

/**
 * Create a share from solved work
 */
ftc_share_t* ftc_p2pool_create_share(ftc_p2pool_t* p2pool,
                                      const char* miner_address,
                                      uint32_t block_height,
                                      const ftc_hash256_t block_hash,
                                      uint32_t nonce);

/**
 * Validate a share
 */
bool ftc_p2pool_validate_share(ftc_p2pool_t* p2pool, const ftc_share_t* share);

/**
 * Add share to PPLNS window
 */
void ftc_p2pool_add_share(ftc_p2pool_t* p2pool, const ftc_share_t* share);

/**
 * Get PPLNS payout distribution
 * Returns array of (address, amount) pairs for coinbase outputs
 * Caller must free the returned array
 */
typedef struct ftc_payout {
    char        address[64];
    uint64_t    amount;
} ftc_payout_t;

ftc_payout_t* ftc_p2pool_get_payouts(ftc_p2pool_t* p2pool,
                                      uint64_t block_reward,
                                      int* payout_count);

/**
 * Create coinbase transaction with P2Pool payouts
 */
ftc_tx_t* ftc_p2pool_create_coinbase(ftc_p2pool_t* p2pool,
                                      uint32_t height,
                                      uint64_t block_reward,
                                      uint64_t fees);

/**
 * Get current share difficulty target
 */
uint32_t ftc_p2pool_get_share_target(ftc_p2pool_t* p2pool);

/**
 * Get P2Pool stats
 */
typedef struct ftc_p2pool_stats {
    uint64_t    total_shares;
    uint64_t    blocks_found;
    int         active_miners;
    uint64_t    pool_hashrate;  /* Estimated from share rate */
    time_t      uptime;
} ftc_p2pool_stats_t;

void ftc_p2pool_get_stats(ftc_p2pool_t* p2pool, ftc_p2pool_stats_t* stats);

/**
 * Serialize/deserialize share for P2P
 */
size_t ftc_share_serialize(const ftc_share_t* share, uint8_t* out, size_t out_size);
ftc_share_t* ftc_share_deserialize(const uint8_t* data, size_t len);

/**
 * Compute share hash
 */
void ftc_share_hash(const ftc_share_t* share, ftc_hash256_t out);

#endif /* FTC_P2POOL_H */
