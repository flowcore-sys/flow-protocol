/**
 * FTC Block Structure
 *
 * Block header, serialization, validation, and genesis block
 */

#ifndef FTC_BLOCK_H
#define FTC_BLOCK_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * BLOCK CREATION
 *============================================================================*/

/**
 * Create new empty block
 */
ftc_block_t* ftc_block_new(void);

/**
 * Create block with header values
 */
ftc_block_t* ftc_block_create(
    uint32_t version,
    const ftc_hash256_t prev_hash,
    uint32_t timestamp,
    uint32_t bits,
    uint32_t nonce
);

/**
 * Free block and all transactions
 */
void ftc_block_free(ftc_block_t* block);

/**
 * Deep copy block
 */
ftc_block_t* ftc_block_copy(const ftc_block_t* block);

/*==============================================================================
 * BLOCK HASHING
 *============================================================================*/

/**
 * Calculate block hash (double Keccak-256 of header)
 */
void ftc_block_hash(const ftc_block_t* block, ftc_hash256_t hash);

/**
 * Calculate Merkle root from block's transactions
 */
void ftc_block_merkle_root(const ftc_block_t* block, ftc_hash256_t root);

/**
 * Update block's Merkle root from its transactions
 */
void ftc_block_update_merkle(ftc_block_t* block);

/*==============================================================================
 * TRANSACTION MANAGEMENT
 *============================================================================*/

/**
 * Add transaction to block
 * Block takes ownership of tx
 */
bool ftc_block_add_tx(ftc_block_t* block, ftc_tx_t* tx);

/**
 * Get transaction by index
 */
ftc_tx_t* ftc_block_get_tx(const ftc_block_t* block, uint32_t index);

/**
 * Get coinbase transaction (first tx)
 */
ftc_tx_t* ftc_block_coinbase(const ftc_block_t* block);

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

/**
 * Serialize block header to 80 bytes
 */
void ftc_block_header_serialize(const ftc_block_header_t* header, uint8_t out[80]);

/**
 * Deserialize block header from 80 bytes
 */
void ftc_block_header_deserialize(const uint8_t data[80], ftc_block_header_t* header);

/**
 * Serialize full block
 * Returns serialized size, 0 on error
 * If out is NULL, returns required size
 */
size_t ftc_block_serialize(const ftc_block_t* block, uint8_t* out, size_t out_len);

/**
 * Deserialize full block
 * Returns block or NULL on error
 */
ftc_block_t* ftc_block_deserialize(const uint8_t* data, size_t len);

/**
 * Serialize block to hex string
 * Returns string (caller must free) or NULL on error
 */
char* ftc_block_to_hex(const ftc_block_t* block);

/**
 * Deserialize block from hex string
 */
ftc_block_t* ftc_block_from_hex(const char* hex);

/*==============================================================================
 * VALIDATION
 *============================================================================*/

/**
 * Validate block structure (not consensus rules)
 */
ftc_error_t ftc_block_validate_structure(const ftc_block_t* block);

/**
 * Check if block hash meets target
 */
bool ftc_block_check_pow(const ftc_block_t* block);

/**
 * Calculate block weight/size
 */
size_t ftc_block_weight(const ftc_block_t* block);

/*==============================================================================
 * DIFFICULTY
 *============================================================================*/

/**
 * Convert compact bits to 256-bit target
 */
void ftc_bits_to_target(uint32_t bits, ftc_hash256_t target);

/**
 * Convert 256-bit target to compact bits
 */
uint32_t ftc_target_to_bits(const ftc_hash256_t target);

/**
 * Calculate difficulty from bits (as double)
 */
double ftc_bits_to_difficulty(uint32_t bits);

/*==============================================================================
 * GENESIS BLOCK
 *============================================================================*/

/**
 * Create genesis block
 */
ftc_block_t* ftc_genesis_block(bool mainnet);

/**
 * Get genesis block hash
 */
void ftc_genesis_hash(bool mainnet, ftc_hash256_t hash);

/**
 * Check if block is genesis block
 */
bool ftc_block_is_genesis(const ftc_block_t* block, bool mainnet);

/*==============================================================================
 * VARINT ENCODING (for serialization)
 *============================================================================*/

/**
 * Encode value as varint
 * Returns bytes written
 */
size_t ftc_varint_encode(uint64_t value, uint8_t* out);

/**
 * Decode varint
 * Returns bytes consumed, 0 on error
 */
size_t ftc_varint_decode(const uint8_t* data, size_t len, uint64_t* value);

/**
 * Get varint encoded size
 */
size_t ftc_varint_size(uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* FTC_BLOCK_H */
