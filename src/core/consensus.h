/**
 * FTC Consensus Rules
 *
 * Difficulty calculation, block validation, and consensus parameters
 */

#ifndef FTC_CONSENSUS_H
#define FTC_CONSENSUS_H

#include "../include/ftc.h"
#include "block.h"
#include "tx.h"
#include "utxo.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * BLOCK INDEX
 *============================================================================*/

typedef struct ftc_block_index {
    ftc_hash256_t           hash;           /* Block hash */
    ftc_hash256_t           prev_hash;      /* Previous block hash */
    uint32_t                height;         /* Block height */
    uint32_t                version;        /* Block version */
    uint32_t                timestamp;      /* Block timestamp */
    uint32_t                bits;           /* Compact difficulty */
    uint32_t                nonce;          /* Nonce */
    ftc_hash256_t           merkle_root;    /* Merkle root */
    uint32_t                tx_count;       /* Number of transactions */
    uint64_t                chain_work;     /* Cumulative chain work */
    struct ftc_block_index* prev;           /* Previous block index */
    struct ftc_block_index* next;           /* Next block index (on best chain) */
    int                     status;         /* Validation status */
} ftc_block_index_t;

/* Block status flags */
#define FTC_BLOCK_VALID_UNKNOWN     0
#define FTC_BLOCK_VALID_HEADER      1
#define FTC_BLOCK_VALID_TREE        2
#define FTC_BLOCK_VALID_TRANSACTIONS 3
#define FTC_BLOCK_VALID_CHAIN       4
#define FTC_BLOCK_VALID_SCRIPTS     5
#define FTC_BLOCK_HAVE_DATA         8
#define FTC_BLOCK_HAVE_UNDO         16
#define FTC_BLOCK_FAILED            32
#define FTC_BLOCK_FAILED_CHILD      64

/*==============================================================================
 * DIFFICULTY CALCULATION
 *============================================================================*/

/**
 * Calculate next difficulty target
 *
 * @param prev_index    Previous block index
 * @param timestamps    Array of last DIFFICULTY_INTERVAL timestamps (newest first)
 * @return New difficulty bits
 */
uint32_t ftc_get_next_difficulty(
    const ftc_block_index_t* prev_index,
    const uint32_t* timestamps
);

/**
 * Calculate work from compact bits
 */
uint64_t ftc_get_block_work(uint32_t bits);

/**
 * Calculate chain work up to and including block
 */
uint64_t ftc_get_chain_work(const ftc_block_index_t* index);

/**
 * Check if difficulty bits are valid
 */
bool ftc_check_difficulty(uint32_t bits);

/*==============================================================================
 * BLOCK VALIDATION
 *============================================================================*/

/**
 * Validate block header (standalone check)
 */
ftc_error_t ftc_validate_block_header(
    const ftc_block_header_t* header,
    const ftc_block_index_t* prev_index
);

/**
 * Validate full block
 */
ftc_error_t ftc_validate_block(
    const ftc_block_t* block,
    const ftc_block_index_t* prev_index,
    const ftc_utxo_set_t* utxo_set
);

/**
 * Validate block contextually (checks that require chain state)
 */
ftc_error_t ftc_validate_block_context(
    const ftc_block_t* block,
    const ftc_block_index_t* prev_index,
    const ftc_utxo_set_t* utxo_set
);

/*==============================================================================
 * TRANSACTION VALIDATION
 *============================================================================*/

/**
 * Validate transaction in context of block
 */
ftc_error_t ftc_validate_transaction(
    const ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height,
    bool is_coinbase
);

/**
 * Validate coinbase transaction
 */
ftc_error_t ftc_validate_coinbase(
    const ftc_tx_t* coinbase,
    uint32_t height,
    uint64_t block_reward,
    uint64_t total_fees
);

/**
 * Check transaction inputs against UTXO set
 */
ftc_error_t ftc_check_tx_inputs(
    const ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
);

/*==============================================================================
 * REWARDS AND FEES
 *============================================================================*/

/**
 * Get block subsidy (new coins) for height
 */
uint64_t ftc_get_block_subsidy(uint32_t height);

/**
 * Calculate maximum allowed block sigops
 */
uint32_t ftc_get_max_sigops(size_t block_size);

/*==============================================================================
 * MEDIAN TIME
 *============================================================================*/

/**
 * Calculate median time past (MTP) for block
 * Uses last 11 blocks
 */
uint32_t ftc_get_median_time_past(const ftc_block_index_t* index);

/**
 * Check if timestamp is valid for new block
 */
bool ftc_check_timestamp(
    uint32_t timestamp,
    const ftc_block_index_t* prev_index
);

/*==============================================================================
 * BLOCK INDEX OPERATIONS
 *============================================================================*/

/**
 * Create block index from block
 */
ftc_block_index_t* ftc_block_index_new(
    const ftc_block_t* block,
    ftc_block_index_t* prev
);

/**
 * Free block index
 */
void ftc_block_index_free(ftc_block_index_t* index);

/**
 * Get ancestor at specific height
 */
ftc_block_index_t* ftc_block_index_ancestor(
    ftc_block_index_t* index,
    uint32_t height
);

/*==============================================================================
 * CHECKPOINTS (Fast Sync)
 *============================================================================*/

/**
 * Set checkpoint height for fast sync
 * Blocks before this height will have minimal validation
 */
void ftc_set_checkpoint_height(uint32_t height);

/**
 * Get current checkpoint height
 */
uint32_t ftc_get_checkpoint_height(void);

#ifdef __cplusplus
}
#endif

#endif /* FTC_CONSENSUS_H */
