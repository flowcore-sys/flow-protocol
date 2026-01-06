/**
 * FTC Merkle Tree Implementation
 */

#include "merkle.h"
#include "keccak256.h"
#include <stdlib.h>
#include <string.h>

/*==============================================================================
 * MERKLE ROOT CALCULATION
 *============================================================================*/

void ftc_merkle_root(
    const ftc_hash256_t* tx_hashes,
    size_t tx_count,
    ftc_hash256_t root
)
{
    if (tx_count == 0) {
        ftc_hash_zero(root);
        return;
    }

    if (tx_count == 1) {
        ftc_hash_copy(root, tx_hashes[0]);
        return;
    }

    /* Calculate tree levels */
    size_t level_size = tx_count;

    /* Allocate working buffer for current level */
    ftc_hash256_t* current = (ftc_hash256_t*)malloc(level_size * sizeof(ftc_hash256_t));
    memcpy(current, tx_hashes, level_size * sizeof(ftc_hash256_t));

    while (level_size > 1) {
        /* If odd number, duplicate last hash */
        size_t pairs = (level_size + 1) / 2;
        ftc_hash256_t* next_level = (ftc_hash256_t*)malloc(pairs * sizeof(ftc_hash256_t));

        for (size_t i = 0; i < pairs; i++) {
            size_t left_idx = i * 2;
            size_t right_idx = i * 2 + 1;

            /* If odd, duplicate left as right */
            if (right_idx >= level_size) {
                right_idx = left_idx;
            }

            /* Concatenate and hash */
            uint8_t concat[64];
            memcpy(concat, current[left_idx], 32);
            memcpy(concat + 32, current[right_idx], 32);

            ftc_keccak256(concat, 64, next_level[i]);
        }

        free(current);
        current = next_level;
        level_size = pairs;
    }

    ftc_hash_copy(root, current[0]);
    free(current);
}

/*==============================================================================
 * MERKLE PROOF
 *============================================================================*/

bool ftc_merkle_proof_create(
    const ftc_hash256_t* tx_hashes,
    size_t tx_count,
    size_t tx_index,
    ftc_merkle_proof_t* proof
)
{
    if (tx_count == 0 || tx_index >= tx_count) {
        return false;
    }

    if (tx_count == 1) {
        proof->hashes = NULL;
        proof->positions = NULL;
        proof->length = 0;
        return true;
    }

    /* Calculate proof depth */
    size_t depth = 0;
    size_t n = tx_count;
    while (n > 1) {
        n = (n + 1) / 2;
        depth++;
    }

    proof->hashes = (ftc_hash256_t*)malloc(depth * sizeof(ftc_hash256_t));
    proof->positions = (bool*)malloc(depth * sizeof(bool));
    proof->length = depth;

    /* Build current level */
    size_t level_size = tx_count;
    ftc_hash256_t* current = (ftc_hash256_t*)malloc(level_size * sizeof(ftc_hash256_t));
    memcpy(current, tx_hashes, level_size * sizeof(ftc_hash256_t));

    size_t idx = tx_index;
    size_t proof_idx = 0;

    while (level_size > 1) {
        /* Get sibling */
        size_t sibling_idx;
        bool is_right;

        if (idx % 2 == 0) {
            sibling_idx = idx + 1;
            is_right = true;
            if (sibling_idx >= level_size) {
                sibling_idx = idx;  /* Duplicate */
            }
        } else {
            sibling_idx = idx - 1;
            is_right = false;
        }

        ftc_hash_copy(proof->hashes[proof_idx], current[sibling_idx]);
        proof->positions[proof_idx] = is_right;
        proof_idx++;

        /* Build next level */
        size_t pairs = (level_size + 1) / 2;
        ftc_hash256_t* next_level = (ftc_hash256_t*)malloc(pairs * sizeof(ftc_hash256_t));

        for (size_t i = 0; i < pairs; i++) {
            size_t left = i * 2;
            size_t right = i * 2 + 1;
            if (right >= level_size) right = left;

            uint8_t concat[64];
            memcpy(concat, current[left], 32);
            memcpy(concat + 32, current[right], 32);
            ftc_keccak256(concat, 64, next_level[i]);
        }

        free(current);
        current = next_level;
        level_size = pairs;
        idx = idx / 2;
    }

    free(current);
    return true;
}

bool ftc_merkle_proof_verify(
    const ftc_hash256_t tx_hash,
    const ftc_merkle_proof_t* proof,
    const ftc_hash256_t root
)
{
    ftc_hash256_t current;
    ftc_hash_copy(current, tx_hash);

    for (size_t i = 0; i < proof->length; i++) {
        uint8_t concat[64];

        if (proof->positions[i]) {
            /* Sibling is on right */
            memcpy(concat, current, 32);
            memcpy(concat + 32, proof->hashes[i], 32);
        } else {
            /* Sibling is on left */
            memcpy(concat, proof->hashes[i], 32);
            memcpy(concat + 32, current, 32);
        }

        ftc_keccak256(concat, 64, current);
    }

    return ftc_hash_compare(current, root) == 0;
}

void ftc_merkle_proof_free(ftc_merkle_proof_t* proof)
{
    if (proof->hashes) {
        free(proof->hashes);
        proof->hashes = NULL;
    }
    if (proof->positions) {
        free(proof->positions);
        proof->positions = NULL;
    }
    proof->length = 0;
}
