/**
 * FTC Transaction Structure
 *
 * UTXO-based transactions with Ed25519 signatures
 */

#ifndef FTC_TX_H
#define FTC_TX_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * TRANSACTION CREATION
 *============================================================================*/

/**
 * Create new empty transaction
 */
ftc_tx_t* ftc_tx_new(void);

/**
 * Create coinbase transaction
 *
 * @param height        Block height (for script)
 * @param reward        Block reward + fees
 * @param script_data   Optional extra data (like message)
 * @param script_len    Length of extra data
 */
ftc_tx_t* ftc_tx_create_coinbase(
    uint32_t height,
    uint64_t reward,
    const uint8_t* script_data,
    size_t script_len
);

/**
 * Free transaction
 */
void ftc_tx_free(ftc_tx_t* tx);

/**
 * Deep copy transaction
 */
ftc_tx_t* ftc_tx_copy(const ftc_tx_t* tx);

/*==============================================================================
 * TRANSACTION BUILDING
 *============================================================================*/

/**
 * Add input to transaction
 *
 * @param tx        Transaction
 * @param txid      Previous transaction hash
 * @param vout      Output index in previous transaction
 * @return true on success
 */
bool ftc_tx_add_input(ftc_tx_t* tx, const ftc_hash256_t txid, uint32_t vout);

/**
 * Add output to transaction
 *
 * @param tx        Transaction
 * @param value     Amount in satoshis
 * @param address   Recipient address (20 bytes)
 * @return true on success
 */
bool ftc_tx_add_output(ftc_tx_t* tx, uint64_t value, const ftc_address_t address);

/**
 * Sign transaction input
 *
 * @param tx        Transaction
 * @param input_idx Input index to sign
 * @param privkey   Private key
 * @param pubkey    Public key
 * @return true on success
 */
bool ftc_tx_sign_input(
    ftc_tx_t* tx,
    uint32_t input_idx,
    const ftc_privkey_t privkey,
    const ftc_pubkey_t pubkey
);

/*==============================================================================
 * TRANSACTION HASHING
 *============================================================================*/

/**
 * Calculate transaction hash (TxID)
 * Single Keccak-256 of serialized tx
 */
void ftc_tx_hash(const ftc_tx_t* tx, ftc_hash256_t hash);

/**
 * Calculate hash for signing (without signatures)
 */
void ftc_tx_sighash(const ftc_tx_t* tx, ftc_hash256_t hash);

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

/**
 * Serialize transaction
 * Returns size, 0 on error
 * If out is NULL, returns required size
 */
size_t ftc_tx_serialize(const ftc_tx_t* tx, uint8_t* out, size_t out_len);

/**
 * Deserialize transaction
 * Returns transaction or NULL on error
 * consumed is set to bytes consumed
 */
ftc_tx_t* ftc_tx_deserialize(const uint8_t* data, size_t len, size_t* consumed);

/**
 * Serialize to hex
 * Returns string (caller must free)
 */
char* ftc_tx_to_hex(const ftc_tx_t* tx);

/**
 * Deserialize from hex
 */
ftc_tx_t* ftc_tx_from_hex(const char* hex);

/*==============================================================================
 * VALIDATION
 *============================================================================*/

/**
 * Basic transaction validation (structure only)
 */
ftc_error_t ftc_tx_validate_structure(const ftc_tx_t* tx);

/**
 * Verify input signature
 */
bool ftc_tx_verify_input(const ftc_tx_t* tx, uint32_t input_idx);

/**
 * Check if transaction is coinbase
 */
bool ftc_tx_is_coinbase(const ftc_tx_t* tx);

/**
 * Get total input value (requires UTXO lookup)
 * Returns 0 if any UTXO not found
 */
typedef uint64_t (*ftc_utxo_lookup_fn)(const ftc_hash256_t txid, uint32_t vout);
uint64_t ftc_tx_input_value(const ftc_tx_t* tx, ftc_utxo_lookup_fn lookup);

/**
 * Get total output value
 */
uint64_t ftc_tx_output_value(const ftc_tx_t* tx);

/**
 * Calculate transaction fee (input_value - output_value)
 */
int64_t ftc_tx_fee(const ftc_tx_t* tx, ftc_utxo_lookup_fn lookup);

/**
 * Get transaction virtual size (for fee calculation)
 */
size_t ftc_tx_vsize(const ftc_tx_t* tx);

/*==============================================================================
 * TXIN/TXOUT HELPERS
 *============================================================================*/

/**
 * Create transaction input
 */
ftc_txin_t* ftc_txin_new(const ftc_hash256_t prev_txid, uint32_t vout);

/**
 * Create transaction output
 */
ftc_txout_t* ftc_txout_new(uint64_t value, const ftc_address_t pubkey_hash);

/**
 * Free transaction input
 */
void ftc_txin_free(ftc_txin_t* txin);

/**
 * Free transaction output
 */
void ftc_txout_free(ftc_txout_t* txout);

/**
 * Check if input is coinbase input
 */
bool ftc_txin_is_coinbase(const ftc_txin_t* txin);

#ifdef __cplusplus
}
#endif

#endif /* FTC_TX_H */
