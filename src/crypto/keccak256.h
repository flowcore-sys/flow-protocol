/**
 * FTC Keccak-256 Implementation
 *
 * SHA-3 (Keccak-256) for:
 * - Block hashing (double Keccak)
 * - Transaction ID
 * - Merkle tree
 * - Address derivation
 */

#ifndef FTC_KECCAK256_H
#define FTC_KECCAK256_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * KECCAK STATE
 *============================================================================*/

typedef struct {
    uint64_t state[25];     /* 5x5 state matrix */
    uint8_t  buffer[136];   /* Rate buffer (1088 bits / 8) */
    size_t   buffer_len;    /* Current buffer position */
} ftc_keccak_ctx_t;

/*==============================================================================
 * BASIC HASHING
 *============================================================================*/

/**
 * Single Keccak-256 hash
 * Used for: TxID, Merkle nodes, address derivation
 */
void ftc_keccak256(const uint8_t* data, size_t len, ftc_hash256_t out);

/**
 * Double Keccak-256 hash
 * Used for: Block hash (PoW)
 */
void ftc_keccak256_double(const uint8_t* data, size_t len, ftc_hash256_t out);

/*==============================================================================
 * STREAMING API
 *============================================================================*/

/**
 * Initialize Keccak context
 */
void ftc_keccak_init(ftc_keccak_ctx_t* ctx);

/**
 * Update with more data
 */
void ftc_keccak_update(ftc_keccak_ctx_t* ctx, const uint8_t* data, size_t len);

/**
 * Finalize and get hash
 */
void ftc_keccak_final(ftc_keccak_ctx_t* ctx, ftc_hash256_t out);

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

/**
 * Hash block header (80 bytes) with double Keccak
 */
void ftc_hash_block_header(const ftc_block_header_t* header, ftc_hash256_t out);

/**
 * Compare two hashes (constant time)
 */
int ftc_hash_compare(const ftc_hash256_t a, const ftc_hash256_t b);

/**
 * Check if hash is zero
 */
bool ftc_hash_is_zero(const ftc_hash256_t hash);

/**
 * Set hash to zero
 */
void ftc_hash_zero(ftc_hash256_t hash);

/**
 * Copy hash
 */
void ftc_hash_copy(ftc_hash256_t dst, const ftc_hash256_t src);

/**
 * Convert hash to hex string
 * Buffer must be at least 65 bytes
 */
void ftc_hash_to_hex(const ftc_hash256_t hash, char* hex);

/**
 * Convert hex string to hash
 * Returns false if invalid hex
 */
bool ftc_hex_to_hash(const char* hex, ftc_hash256_t hash);

/**
 * Reverse hash bytes (for display)
 */
void ftc_hash_reverse(const ftc_hash256_t in, ftc_hash256_t out);

#ifdef __cplusplus
}
#endif

#endif /* FTC_KECCAK256_H */
