/**
 * FTC Consensus Implementation
 */

#include "consensus.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*==============================================================================
 * DIFFICULTY CALCULATION
 *============================================================================*/

/* Maximum target (minimum difficulty) */
static const ftc_hash256_t MAX_TARGET = {
    0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint32_t ftc_get_next_difficulty(
    const ftc_block_index_t* prev_index,
    const uint32_t* timestamps
)
{
    if (!prev_index) {
        return FTC_GENESIS_BITS;
    }

    uint32_t height = prev_index->height + 1;

    /* Only adjust at interval boundaries */
    if (height % FTC_DIFFICULTY_INTERVAL != 0) {
        return prev_index->bits;
    }

    /* Calculate actual time span */
    uint32_t first_time = timestamps[FTC_DIFFICULTY_INTERVAL - 1];
    uint32_t last_time = timestamps[0];

    int32_t actual_time = (int32_t)(last_time - first_time);
    int32_t target_time = FTC_TARGET_BLOCK_TIME * FTC_DIFFICULTY_INTERVAL;

    /* Limit adjustment to 4x in either direction */
    if (actual_time < target_time / 4) {
        actual_time = target_time / 4;
    }
    if (actual_time > target_time * 4) {
        actual_time = target_time * 4;
    }

    /* Calculate new target */
    ftc_hash256_t current_target, new_target;
    ftc_bits_to_target(prev_index->bits, current_target);

    /* new_target = current_target * actual_time / target_time */
    /* Use simple byte-wise multiplication with 32-bit math for portability */

    /* Work with uint32_t limbs for cross-platform compatibility */
    uint32_t target_u32[8] = {0};
    for (int i = 0; i < 8; i++) {
        target_u32[i] = (uint32_t)current_target[i * 4] |
                        ((uint32_t)current_target[i * 4 + 1] << 8) |
                        ((uint32_t)current_target[i * 4 + 2] << 16) |
                        ((uint32_t)current_target[i * 4 + 3] << 24);
    }

    /* Multiply by actual_time (fits in 32 bits) */
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t prod = (uint64_t)target_u32[i] * (uint32_t)actual_time + carry;
        target_u32[i] = (uint32_t)prod;
        carry = prod >> 32;
    }

    /* Divide by target_time */
    uint64_t remainder = 0;
    for (int i = 7; i >= 0; i--) {
        uint64_t dividend = (remainder << 32) | target_u32[i];
        target_u32[i] = (uint32_t)(dividend / (uint32_t)target_time);
        remainder = dividend % (uint32_t)target_time;
    }

    /* Convert back to bytes */
    for (int i = 0; i < 8; i++) {
        new_target[i * 4] = (uint8_t)(target_u32[i] & 0xff);
        new_target[i * 4 + 1] = (uint8_t)((target_u32[i] >> 8) & 0xff);
        new_target[i * 4 + 2] = (uint8_t)((target_u32[i] >> 16) & 0xff);
        new_target[i * 4 + 3] = (uint8_t)((target_u32[i] >> 24) & 0xff);
    }

    /* Clamp to max target */
    if (ftc_hash_compare(new_target, MAX_TARGET) > 0) {
        memcpy(new_target, MAX_TARGET, 32);
    }

    return ftc_target_to_bits(new_target);
}

uint64_t ftc_get_block_work(uint32_t bits)
{
    ftc_hash256_t target;
    ftc_bits_to_target(bits, target);

    /* Work = 2^256 / (target + 1) */
    /* Approximate as: 2^64 / (target[24..31] as u64) */

    uint64_t target_high = 0;
    for (int i = 24; i < 32; i++) {
        target_high = (target_high << 8) | target[31 - i + 24];
    }

    if (target_high == 0) return 0;
    return UINT64_MAX / target_high;
}

uint64_t ftc_get_chain_work(const ftc_block_index_t* index)
{
    return index ? index->chain_work : 0;
}

bool ftc_check_difficulty(uint32_t bits)
{
    ftc_hash256_t target;
    ftc_bits_to_target(bits, target);

    /* Target must be positive and not exceed max */
    if (ftc_hash_is_zero(target)) return false;
    if (ftc_hash_compare(target, MAX_TARGET) > 0) return false;

    return true;
}

/*==============================================================================
 * BLOCK VALIDATION
 *============================================================================*/

ftc_error_t ftc_validate_block_header(
    const ftc_block_header_t* header,
    const ftc_block_index_t* prev_index
)
{
    if (!header) return FTC_ERR_INVALID_PARAM;

    /* Check version */
    if (header->version < 1) {
        return FTC_ERR_INVALID_BLOCK;
    }

    /* Check difficulty */
    if (!ftc_check_difficulty(header->bits)) {
        return FTC_ERR_INVALID_DIFFICULTY;
    }

    /* Check proof of work */
    ftc_hash256_t hash, target;
    ftc_hash_block_header(header, hash);
    ftc_bits_to_target(header->bits, target);

    if (ftc_hash_compare(hash, target) > 0) {
        return FTC_ERR_INVALID_BLOCK;
    }

    /* If we have previous block, check chain rules */
    if (prev_index) {
        /* Previous hash must match */
        if (memcmp(header->prev_hash, prev_index->hash, 32) != 0) {
            return FTC_ERR_INVALID_BLOCK;
        }

        /* Timestamp must be greater than median time past */
        uint32_t mtp = ftc_get_median_time_past(prev_index);
        if (header->timestamp <= mtp) {
            return FTC_ERR_BLOCK_TOO_OLD;
        }

        /* Timestamp must not be too far in future */
        uint32_t max_time = (uint32_t)time(NULL) + FTC_MAX_FUTURE_TIME;
        if (header->timestamp > max_time) {
            return FTC_ERR_BLOCK_TOO_NEW;
        }
    }

    return FTC_OK;
}

ftc_error_t ftc_validate_block(
    const ftc_block_t* block,
    const ftc_block_index_t* prev_index,
    const ftc_utxo_set_t* utxo_set
)
{
    if (!block) return FTC_ERR_INVALID_PARAM;

    /* Validate header */
    ftc_error_t err = ftc_validate_block_header(&block->header, prev_index);
    if (err != FTC_OK) return err;

    /* Basic structure validation */
    err = ftc_block_validate_structure(block);
    if (err != FTC_OK) return err;

    /* Check block size */
    size_t size = ftc_block_serialize(block, NULL, 0);
    if (size > FTC_MAX_BLOCK_SIZE) {
        return FTC_ERR_INVALID_BLOCK;
    }

    /* Calculate height */
    uint32_t height = prev_index ? prev_index->height + 1 : 0;

    /* Calculate total fees and validate transactions */
    uint64_t total_fees = 0;

    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_tx_t* tx = block->transactions[i];
        bool is_coinbase = (i == 0);

        err = ftc_validate_transaction(tx, utxo_set, height, is_coinbase);
        if (err != FTC_OK) return err;

        if (!is_coinbase) {
            /* Calculate fee (requires UTXO lookup) */
            /* In production, this would use the UTXO set */
        }
    }

    /* Validate coinbase */
    uint64_t block_subsidy = ftc_get_block_subsidy(height);
    ftc_tx_t* coinbase = ftc_block_coinbase(block);

    err = ftc_validate_coinbase(coinbase, height, block_subsidy, total_fees);
    if (err != FTC_OK) return err;

    return FTC_OK;
}

ftc_error_t ftc_validate_block_context(
    const ftc_block_t* block,
    const ftc_block_index_t* prev_index,
    const ftc_utxo_set_t* utxo_set
)
{
    if (!block || !prev_index) return FTC_ERR_INVALID_PARAM;

    /* Check that all inputs exist and are spendable */
    uint32_t height = prev_index->height + 1;

    for (uint32_t i = 1; i < block->tx_count; i++) {  /* Skip coinbase */
        ftc_tx_t* tx = block->transactions[i];

        ftc_error_t err = ftc_check_tx_inputs(tx, utxo_set, height);
        if (err != FTC_OK) return err;
    }

    return FTC_OK;
}

/*==============================================================================
 * TRANSACTION VALIDATION
 *============================================================================*/

ftc_error_t ftc_validate_transaction(
    const ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height,
    bool is_coinbase
)
{
    if (!tx) return FTC_ERR_INVALID_PARAM;

    /* Basic structure */
    ftc_error_t err = ftc_tx_validate_structure(tx);
    if (err != FTC_OK) return err;

    if (is_coinbase) {
        /* Coinbase has special rules */
        if (!ftc_tx_is_coinbase(tx)) {
            return FTC_ERR_INVALID_TX;
        }
    } else {
        /* Regular transaction */
        if (ftc_tx_is_coinbase(tx)) {
            return FTC_ERR_INVALID_TX;
        }

        /* Verify all input signatures */
        for (uint32_t i = 0; i < tx->input_count; i++) {
            if (!ftc_tx_verify_input(tx, i)) {
                return FTC_ERR_INVALID_SIGNATURE;
            }
        }
    }

    return FTC_OK;
}

ftc_error_t ftc_validate_coinbase(
    const ftc_tx_t* coinbase,
    uint32_t height,
    uint64_t block_reward,
    uint64_t total_fees
)
{
    if (!coinbase) return FTC_ERR_INVALID_PARAM;

    if (!ftc_tx_is_coinbase(coinbase)) {
        return FTC_ERR_INVALID_TX;
    }

    /* Calculate total output value */
    uint64_t total_output = ftc_tx_output_value(coinbase);

    /* Output must not exceed reward + fees */
    uint64_t max_output = block_reward + total_fees;
    if (total_output > max_output) {
        return FTC_ERR_INVALID_TX;
    }

    return FTC_OK;
}

ftc_error_t ftc_check_tx_inputs(
    const ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
)
{
    if (!tx || !utxo_set) return FTC_ERR_INVALID_PARAM;

    if (ftc_tx_is_coinbase(tx)) {
        return FTC_OK;
    }

    uint64_t total_input = 0;

    for (uint32_t i = 0; i < tx->input_count; i++) {
        /* Look up UTXO */
        const ftc_utxo_t* utxo = ftc_utxo_set_get(
            utxo_set,
            tx->inputs[i].prev_txid,
            tx->inputs[i].vout
        );

        if (!utxo) {
            return FTC_ERR_INVALID_UTXO;
        }

        /* Check if spendable (coinbase maturity) */
        if (!ftc_utxo_is_spendable(utxo, height)) {
            return FTC_ERR_INVALID_UTXO;
        }

        /* Verify that pubkey matches UTXO */
        ftc_address_t address;
        ftc_address_from_pubkey(tx->inputs[i].pubkey, address);

        if (memcmp(address, utxo->pubkey_hash, 20) != 0) {
            return FTC_ERR_INVALID_SIGNATURE;
        }

        total_input += utxo->value;
    }

    /* Inputs must cover outputs + fee */
    uint64_t total_output = ftc_tx_output_value(tx);
    if (total_input < total_output) {
        return FTC_ERR_INSUFFICIENT_FUNDS;
    }

    return FTC_OK;
}

/*==============================================================================
 * REWARDS AND FEES
 *============================================================================*/

uint64_t ftc_get_block_subsidy(uint32_t height)
{
    return ftc_get_block_reward(height);
}

uint32_t ftc_get_max_sigops(size_t block_size)
{
    return FTC_MAX_BLOCK_SIGOPS;
}

/*==============================================================================
 * MEDIAN TIME
 *============================================================================*/

#define MTP_BLOCKS 11

uint32_t ftc_get_median_time_past(const ftc_block_index_t* index)
{
    if (!index) return 0;

    uint32_t timestamps[MTP_BLOCKS];
    int count = 0;

    const ftc_block_index_t* current = index;
    while (current && count < MTP_BLOCKS) {
        timestamps[count++] = current->timestamp;
        current = current->prev;
    }

    if (count == 0) return 0;

    /* Sort timestamps */
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (timestamps[j] < timestamps[i]) {
                uint32_t tmp = timestamps[i];
                timestamps[i] = timestamps[j];
                timestamps[j] = tmp;
            }
        }
    }

    return timestamps[count / 2];
}

bool ftc_check_timestamp(
    uint32_t timestamp,
    const ftc_block_index_t* prev_index
)
{
    /* Must be greater than MTP */
    uint32_t mtp = ftc_get_median_time_past(prev_index);
    if (timestamp <= mtp) return false;

    /* Must not be too far in future */
    uint32_t max_time = (uint32_t)time(NULL) + FTC_MAX_FUTURE_TIME;
    if (timestamp > max_time) return false;

    return true;
}

/*==============================================================================
 * BLOCK INDEX OPERATIONS
 *============================================================================*/

ftc_block_index_t* ftc_block_index_new(
    const ftc_block_t* block,
    ftc_block_index_t* prev
)
{
    if (!block) return NULL;

    ftc_block_index_t* index = (ftc_block_index_t*)calloc(1, sizeof(ftc_block_index_t));
    if (!index) return NULL;

    /* Calculate hash */
    ftc_block_hash(block, index->hash);

    /* Copy header fields */
    memcpy(index->prev_hash, block->header.prev_hash, 32);
    index->version = block->header.version;
    index->timestamp = block->header.timestamp;
    index->bits = block->header.bits;
    index->nonce = block->header.nonce;
    memcpy(index->merkle_root, block->header.merkle_root, 32);
    index->tx_count = block->tx_count;

    /* Set chain info */
    index->prev = prev;
    if (prev) {
        index->height = prev->height + 1;
        index->chain_work = prev->chain_work + ftc_get_block_work(index->bits);
        prev->next = index;
    } else {
        index->height = 0;
        index->chain_work = ftc_get_block_work(index->bits);
    }

    index->status = FTC_BLOCK_VALID_HEADER;

    return index;
}

void ftc_block_index_free(ftc_block_index_t* index)
{
    free(index);
}

ftc_block_index_t* ftc_block_index_ancestor(
    ftc_block_index_t* index,
    uint32_t height
)
{
    if (!index || height > index->height) return NULL;

    ftc_block_index_t* current = index;
    while (current && current->height > height) {
        current = current->prev;
    }

    return current;
}
