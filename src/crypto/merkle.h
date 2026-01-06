/**
 * FTC Merkle Tree Implementation
 *
 * Merkle root calculation for transaction trees
 */

#ifndef FTC_MERKLE_H
#define FTC_MERKLE_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Calculate Merkle root from transaction hashes
 *
 * @param tx_hashes Array of transaction hashes
 * @param tx_count  Number of transactions
 * @param root      Output: Merkle root hash
 */
void ftc_merkle_root(
    const ftc_hash256_t* tx_hashes,
    size_t tx_count,
    ftc_hash256_t root
);

/**
 * Merkle proof structure
 */
typedef struct {
    ftc_hash256_t* hashes;      /* Proof hashes */
    bool* positions;            /* true = right, false = left */
    size_t length;              /* Number of proof elements */
} ftc_merkle_proof_t;

/**
 * Generate Merkle proof for a transaction
 *
 * @param tx_hashes Array of transaction hashes
 * @param tx_count  Number of transactions
 * @param tx_index  Index of transaction to prove
 * @param proof     Output: Merkle proof (caller must free)
 * @return true on success
 */
bool ftc_merkle_proof_create(
    const ftc_hash256_t* tx_hashes,
    size_t tx_count,
    size_t tx_index,
    ftc_merkle_proof_t* proof
);

/**
 * Verify Merkle proof
 *
 * @param tx_hash   Transaction hash
 * @param proof     Merkle proof
 * @param root      Expected Merkle root
 * @return true if proof is valid
 */
bool ftc_merkle_proof_verify(
    const ftc_hash256_t tx_hash,
    const ftc_merkle_proof_t* proof,
    const ftc_hash256_t root
);

/**
 * Free Merkle proof
 */
void ftc_merkle_proof_free(ftc_merkle_proof_t* proof);

#ifdef __cplusplus
}
#endif

#endif /* FTC_MERKLE_H */
