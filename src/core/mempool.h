/**
 * FTC Memory Pool
 *
 * Pending transaction management with fee-based priority
 */

#ifndef FTC_MEMPOOL_H
#define FTC_MEMPOOL_H

#include "../include/ftc.h"
#include "tx.h"
#include "utxo.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * MEMPOOL ENTRY
 *============================================================================*/

typedef struct {
    ftc_tx_t*       tx;             /* Transaction */
    ftc_hash256_t   txid;           /* Transaction hash */
    uint64_t        fee;            /* Transaction fee */
    size_t          size;           /* Serialized size */
    double          fee_rate;       /* Fee per byte */
    uint64_t        time;           /* Time added to mempool */
    uint32_t        height;         /* Block height when added */
    int             priority;       /* Priority score */
} ftc_mempool_entry_t;

/*==============================================================================
 * MEMPOOL
 *============================================================================*/

/* Forward declaration */
typedef struct ftc_mempool ftc_mempool_t;

/**
 * Create new mempool
 *
 * @param max_size  Maximum memory pool size in bytes
 */
ftc_mempool_t* ftc_mempool_new(size_t max_size);

/**
 * Free mempool
 */
void ftc_mempool_free(ftc_mempool_t* mempool);

/*==============================================================================
 * TRANSACTION MANAGEMENT
 *============================================================================*/

/**
 * Add transaction to mempool
 *
 * @param mempool   Memory pool
 * @param tx        Transaction (mempool takes ownership)
 * @param utxo_set  UTXO set for validation
 * @param height    Current chain height
 * @return FTC_OK on success
 */
ftc_error_t ftc_mempool_add(
    ftc_mempool_t* mempool,
    ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
);

/**
 * Remove transaction from mempool
 *
 * @param mempool   Memory pool
 * @param txid      Transaction hash
 * @return Removed transaction (caller owns) or NULL
 */
ftc_tx_t* ftc_mempool_remove(
    ftc_mempool_t* mempool,
    const ftc_hash256_t txid
);

/**
 * Get transaction from mempool (without removing)
 */
const ftc_tx_t* ftc_mempool_get(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
);

/**
 * Check if transaction is in mempool
 */
bool ftc_mempool_has(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
);

/**
 * Get mempool entry (with metadata)
 */
const ftc_mempool_entry_t* ftc_mempool_get_entry(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
);

/*==============================================================================
 * BLOCK OPERATIONS
 *============================================================================*/

/**
 * Remove transactions that are in a block
 *
 * @param mempool   Memory pool
 * @param block     Block containing transactions to remove
 */
void ftc_mempool_remove_block(
    ftc_mempool_t* mempool,
    const ftc_block_t* block
);

/**
 * Add back transactions from disconnected block
 *
 * @param mempool   Memory pool
 * @param block     Disconnected block
 * @param utxo_set  Current UTXO set
 * @param height    Current height
 */
void ftc_mempool_add_block(
    ftc_mempool_t* mempool,
    const ftc_block_t* block,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
);

/*==============================================================================
 * TRANSACTION SELECTION (for mining)
 *============================================================================*/

/**
 * Get transactions for new block sorted by fee rate
 *
 * @param mempool       Memory pool
 * @param max_size      Maximum total size in bytes
 * @param out_txs       Output array of transactions
 * @param out_count     Output: number of transactions
 * @param out_fees      Output: total fees
 * @return true on success
 */
bool ftc_mempool_select_transactions(
    const ftc_mempool_t* mempool,
    size_t max_size,
    ftc_tx_t*** out_txs,
    size_t* out_count,
    uint64_t* out_fees
);

/*==============================================================================
 * MEMPOOL STATUS
 *============================================================================*/

/**
 * Get number of transactions in mempool
 */
size_t ftc_mempool_count(const ftc_mempool_t* mempool);

/**
 * Get total size of mempool in bytes
 */
size_t ftc_mempool_size(const ftc_mempool_t* mempool);

/**
 * Get mempool info
 */
typedef struct {
    size_t  tx_count;       /* Number of transactions */
    size_t  total_size;     /* Total size in bytes */
    size_t  max_size;       /* Maximum size */
    uint64_t total_fees;    /* Total fees in mempool */
    double  min_fee_rate;   /* Minimum fee rate to enter */
} ftc_mempool_info_t;

void ftc_mempool_info(const ftc_mempool_t* mempool, ftc_mempool_info_t* info);

/*==============================================================================
 * DOUBLE SPEND DETECTION
 *============================================================================*/

/**
 * Check if any input is already spent by mempool transaction
 */
bool ftc_mempool_check_double_spend(
    const ftc_mempool_t* mempool,
    const ftc_tx_t* tx
);

/*==============================================================================
 * EVICTION
 *============================================================================*/

/**
 * Evict lowest fee-rate transactions to make room
 *
 * @param mempool   Memory pool
 * @param bytes     Bytes to free
 * @return true if enough space was freed
 */
bool ftc_mempool_evict(ftc_mempool_t* mempool, size_t bytes);

/**
 * Clear entire mempool
 */
void ftc_mempool_clear(ftc_mempool_t* mempool);

#ifdef __cplusplus
}
#endif

#endif /* FTC_MEMPOOL_H */
