/**
 * FTC UTXO Set Management
 *
 * Unspent Transaction Output tracking
 */

#ifndef FTC_UTXO_H
#define FTC_UTXO_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * UTXO SET
 *============================================================================*/

/* Forward declaration */
typedef struct ftc_utxo_set ftc_utxo_set_t;

/**
 * Create new UTXO set
 */
ftc_utxo_set_t* ftc_utxo_set_new(void);

/**
 * Free UTXO set
 */
void ftc_utxo_set_free(ftc_utxo_set_t* set);

/**
 * Add UTXO to set
 */
bool ftc_utxo_set_add(ftc_utxo_set_t* set, const ftc_utxo_t* utxo);

/**
 * Remove UTXO from set
 * Returns the removed UTXO (caller must free) or NULL
 */
ftc_utxo_t* ftc_utxo_set_remove(
    ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
);

/**
 * Get UTXO from set (does not remove)
 * Returns pointer to UTXO or NULL
 */
const ftc_utxo_t* ftc_utxo_set_get(
    const ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
);

/**
 * Check if UTXO exists
 */
bool ftc_utxo_set_has(
    const ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
);

/**
 * Get number of UTXOs in set
 */
size_t ftc_utxo_set_count(const ftc_utxo_set_t* set);

/**
 * Get total value in set
 */
uint64_t ftc_utxo_set_total_value(const ftc_utxo_set_t* set);

/*==============================================================================
 * ADDRESS LOOKUP
 *============================================================================*/

/**
 * Get all UTXOs for an address
 *
 * @param set       UTXO set
 * @param address   Address to look up (20 bytes)
 * @param out       Output array (allocated by function)
 * @param count     Output: number of UTXOs found
 * @return true on success (even if count is 0)
 */
bool ftc_utxo_set_get_by_address(
    const ftc_utxo_set_t* set,
    const ftc_address_t address,
    ftc_utxo_t** out,
    size_t* count
);

/**
 * Calculate balance for address
 */
uint64_t ftc_utxo_set_balance(
    const ftc_utxo_set_t* set,
    const ftc_address_t address
);

/*==============================================================================
 * BLOCK OPERATIONS
 *============================================================================*/

/**
 * Connect block to UTXO set (add new outputs, remove spent inputs)
 *
 * @param set       UTXO set
 * @param block     Block to connect
 * @param height    Block height
 * @return FTC_OK on success
 */
ftc_error_t ftc_utxo_set_connect_block(
    ftc_utxo_set_t* set,
    const ftc_block_t* block,
    uint32_t height
);

/**
 * Disconnect block from UTXO set (reverse connect)
 *
 * @param set       UTXO set
 * @param block     Block to disconnect
 * @param height    Block height
 * @return FTC_OK on success
 */
ftc_error_t ftc_utxo_set_disconnect_block(
    ftc_utxo_set_t* set,
    const ftc_block_t* block,
    uint32_t height
);

/*==============================================================================
 * UTXO CREATION
 *============================================================================*/

/**
 * Create UTXO from transaction output
 */
ftc_utxo_t* ftc_utxo_new(
    const ftc_hash256_t txid,
    uint32_t vout,
    uint64_t value,
    const ftc_address_t pubkey_hash,
    uint32_t height,
    bool coinbase
);

/**
 * Free UTXO
 */
void ftc_utxo_free(ftc_utxo_t* utxo);

/**
 * Copy UTXO
 */
ftc_utxo_t* ftc_utxo_copy(const ftc_utxo_t* utxo);

/**
 * Check if UTXO is spendable (coinbase maturity)
 */
bool ftc_utxo_is_spendable(const ftc_utxo_t* utxo, uint32_t current_height);

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

/**
 * Serialize UTXO
 */
size_t ftc_utxo_serialize(const ftc_utxo_t* utxo, uint8_t* out, size_t out_len);

/**
 * Deserialize UTXO
 */
ftc_utxo_t* ftc_utxo_deserialize(const uint8_t* data, size_t len);

/*==============================================================================
 * OUTPOINT (txid:vout)
 *============================================================================*/

typedef struct {
    ftc_hash256_t txid;
    uint32_t vout;
} ftc_outpoint_t;

/**
 * Create outpoint key for database lookup
 * Buffer must be at least 36 bytes
 */
void ftc_outpoint_key(const ftc_hash256_t txid, uint32_t vout, uint8_t out[36]);

/**
 * Compare two outpoints
 */
int ftc_outpoint_compare(const ftc_outpoint_t* a, const ftc_outpoint_t* b);

#ifdef __cplusplus
}
#endif

#endif /* FTC_UTXO_H */
