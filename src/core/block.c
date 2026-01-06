/**
 * FTC Block Implementation
 */

#include "block.h"
#include "tx.h"
#include "../crypto/keccak256.h"
#include "../crypto/merkle.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*==============================================================================
 * VARINT ENCODING
 *============================================================================*/

size_t ftc_varint_encode(uint64_t value, uint8_t* out)
{
    if (value < 0xfd) {
        out[0] = (uint8_t)value;
        return 1;
    } else if (value <= 0xffff) {
        out[0] = 0xfd;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        return 3;
    } else if (value <= 0xffffffff) {
        out[0] = 0xfe;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        out[3] = (uint8_t)((value >> 16) & 0xff);
        out[4] = (uint8_t)((value >> 24) & 0xff);
        return 5;
    } else {
        out[0] = 0xff;
        for (int i = 0; i < 8; i++) {
            out[1 + i] = (uint8_t)((value >> (i * 8)) & 0xff);
        }
        return 9;
    }
}

size_t ftc_varint_decode(const uint8_t* data, size_t len, uint64_t* value)
{
    if (len == 0) return 0;

    if (data[0] < 0xfd) {
        *value = data[0];
        return 1;
    } else if (data[0] == 0xfd) {
        if (len < 3) return 0;
        *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8);
        return 3;
    } else if (data[0] == 0xfe) {
        if (len < 5) return 0;
        *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
                 ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24);
        return 5;
    } else {
        if (len < 9) return 0;
        *value = 0;
        for (int i = 0; i < 8; i++) {
            *value |= ((uint64_t)data[1 + i] << (i * 8));
        }
        return 9;
    }
}

size_t ftc_varint_size(uint64_t value)
{
    if (value < 0xfd) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
}

/*==============================================================================
 * BLOCK CREATION
 *============================================================================*/

ftc_block_t* ftc_block_new(void)
{
    ftc_block_t* block = (ftc_block_t*)calloc(1, sizeof(ftc_block_t));
    if (!block) return NULL;

    block->header.version = 1;
    return block;
}

ftc_block_t* ftc_block_create(
    uint32_t version,
    const ftc_hash256_t prev_hash,
    uint32_t timestamp,
    uint32_t bits,
    uint32_t nonce
)
{
    ftc_block_t* block = ftc_block_new();
    if (!block) return NULL;

    block->header.version = version;
    if (prev_hash) {
        memcpy(block->header.prev_hash, prev_hash, 32);
    }
    block->header.timestamp = timestamp;
    block->header.bits = bits;
    block->header.nonce = nonce;

    return block;
}

void ftc_block_free(ftc_block_t* block)
{
    if (!block) return;

    /* Free all transactions */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        if (block->transactions[i]) {
            ftc_tx_free(block->transactions[i]);
        }
    }

    if (block->transactions) {
        free(block->transactions);
    }

    free(block);
}

ftc_block_t* ftc_block_copy(const ftc_block_t* block)
{
    if (!block) return NULL;

    ftc_block_t* copy = ftc_block_new();
    if (!copy) return NULL;

    /* Copy header */
    memcpy(&copy->header, &block->header, sizeof(ftc_block_header_t));

    /* Copy transactions */
    if (block->tx_count > 0) {
        copy->transactions = (ftc_tx_t**)calloc(block->tx_count, sizeof(ftc_tx_t*));
        if (!copy->transactions) {
            ftc_block_free(copy);
            return NULL;
        }

        for (uint32_t i = 0; i < block->tx_count; i++) {
            copy->transactions[i] = ftc_tx_copy(block->transactions[i]);
            if (!copy->transactions[i]) {
                ftc_block_free(copy);
                return NULL;
            }
            copy->tx_count++;
        }
    }

    return copy;
}

/*==============================================================================
 * BLOCK HASHING
 *============================================================================*/

void ftc_block_hash(const ftc_block_t* block, ftc_hash256_t hash)
{
    ftc_hash_block_header(&block->header, hash);
}

void ftc_block_merkle_root(const ftc_block_t* block, ftc_hash256_t root)
{
    if (block->tx_count == 0) {
        ftc_hash_zero(root);
        return;
    }

    /* Compute transaction hashes */
    ftc_hash256_t* tx_hashes = (ftc_hash256_t*)malloc(block->tx_count * sizeof(ftc_hash256_t));
    if (!tx_hashes) {
        ftc_hash_zero(root);
        return;
    }

    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_tx_hash(block->transactions[i], tx_hashes[i]);
    }

    ftc_merkle_root(tx_hashes, block->tx_count, root);
    free(tx_hashes);
}

void ftc_block_update_merkle(ftc_block_t* block)
{
    ftc_block_merkle_root(block, block->header.merkle_root);
}

/*==============================================================================
 * TRANSACTION MANAGEMENT
 *============================================================================*/

bool ftc_block_add_tx(ftc_block_t* block, ftc_tx_t* tx)
{
    if (!block || !tx) return false;

    /* Resize array */
    ftc_tx_t** new_txs = (ftc_tx_t**)realloc(
        block->transactions,
        (block->tx_count + 1) * sizeof(ftc_tx_t*)
    );
    if (!new_txs) return false;

    block->transactions = new_txs;
    block->transactions[block->tx_count] = tx;
    block->tx_count++;

    return true;
}

ftc_tx_t* ftc_block_get_tx(const ftc_block_t* block, uint32_t index)
{
    if (!block || index >= block->tx_count) return NULL;
    return block->transactions[index];
}

ftc_tx_t* ftc_block_coinbase(const ftc_block_t* block)
{
    return ftc_block_get_tx(block, 0);
}

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

void ftc_block_header_serialize(const ftc_block_header_t* header, uint8_t out[80])
{
    size_t pos = 0;

    /* Version (4 bytes, little-endian) */
    out[pos++] = (uint8_t)(header->version & 0xff);
    out[pos++] = (uint8_t)((header->version >> 8) & 0xff);
    out[pos++] = (uint8_t)((header->version >> 16) & 0xff);
    out[pos++] = (uint8_t)((header->version >> 24) & 0xff);

    /* Previous hash (32 bytes) */
    memcpy(out + pos, header->prev_hash, 32);
    pos += 32;

    /* Merkle root (32 bytes) */
    memcpy(out + pos, header->merkle_root, 32);
    pos += 32;

    /* Timestamp (4 bytes, little-endian) */
    out[pos++] = (uint8_t)(header->timestamp & 0xff);
    out[pos++] = (uint8_t)((header->timestamp >> 8) & 0xff);
    out[pos++] = (uint8_t)((header->timestamp >> 16) & 0xff);
    out[pos++] = (uint8_t)((header->timestamp >> 24) & 0xff);

    /* Bits (4 bytes, little-endian) */
    out[pos++] = (uint8_t)(header->bits & 0xff);
    out[pos++] = (uint8_t)((header->bits >> 8) & 0xff);
    out[pos++] = (uint8_t)((header->bits >> 16) & 0xff);
    out[pos++] = (uint8_t)((header->bits >> 24) & 0xff);

    /* Nonce (4 bytes, little-endian) */
    out[pos++] = (uint8_t)(header->nonce & 0xff);
    out[pos++] = (uint8_t)((header->nonce >> 8) & 0xff);
    out[pos++] = (uint8_t)((header->nonce >> 16) & 0xff);
    out[pos++] = (uint8_t)((header->nonce >> 24) & 0xff);
}

void ftc_block_header_deserialize(const uint8_t data[80], ftc_block_header_t* header)
{
    size_t pos = 0;

    /* Version */
    header->version = (uint32_t)data[pos] |
                      ((uint32_t)data[pos + 1] << 8) |
                      ((uint32_t)data[pos + 2] << 16) |
                      ((uint32_t)data[pos + 3] << 24);
    pos += 4;

    /* Previous hash */
    memcpy(header->prev_hash, data + pos, 32);
    pos += 32;

    /* Merkle root */
    memcpy(header->merkle_root, data + pos, 32);
    pos += 32;

    /* Timestamp */
    header->timestamp = (uint32_t)data[pos] |
                        ((uint32_t)data[pos + 1] << 8) |
                        ((uint32_t)data[pos + 2] << 16) |
                        ((uint32_t)data[pos + 3] << 24);
    pos += 4;

    /* Bits */
    header->bits = (uint32_t)data[pos] |
                   ((uint32_t)data[pos + 1] << 8) |
                   ((uint32_t)data[pos + 2] << 16) |
                   ((uint32_t)data[pos + 3] << 24);
    pos += 4;

    /* Nonce */
    header->nonce = (uint32_t)data[pos] |
                    ((uint32_t)data[pos + 1] << 8) |
                    ((uint32_t)data[pos + 2] << 16) |
                    ((uint32_t)data[pos + 3] << 24);
}

size_t ftc_block_serialize(const ftc_block_t* block, uint8_t* out, size_t out_len)
{
    if (!block) return 0;

    /* Calculate required size */
    size_t size = 80;  /* Header */
    size += ftc_varint_size(block->tx_count);  /* TX count */

    for (uint32_t i = 0; i < block->tx_count; i++) {
        size += ftc_tx_serialize(block->transactions[i], NULL, 0);
    }

    if (!out) return size;
    if (out_len < size) return 0;

    size_t pos = 0;

    /* Header */
    ftc_block_header_serialize(&block->header, out);
    pos += 80;

    /* TX count */
    pos += ftc_varint_encode(block->tx_count, out + pos);

    /* Transactions */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        size_t tx_size = ftc_tx_serialize(block->transactions[i], out + pos, out_len - pos);
        if (tx_size == 0) return 0;
        pos += tx_size;
    }

    return pos;
}

ftc_block_t* ftc_block_deserialize(const uint8_t* data, size_t len)
{
    if (!data || len < 80) return NULL;

    ftc_block_t* block = ftc_block_new();
    if (!block) return NULL;

    size_t pos = 0;

    /* Header */
    ftc_block_header_deserialize(data, &block->header);
    pos += 80;

    /* TX count */
    uint64_t tx_count;
    size_t varint_len = ftc_varint_decode(data + pos, len - pos, &tx_count);
    if (varint_len == 0 || tx_count > 100000) {
        ftc_block_free(block);
        return NULL;
    }
    pos += varint_len;

    /* Transactions */
    for (uint64_t i = 0; i < tx_count; i++) {
        size_t tx_size;
        ftc_tx_t* tx = ftc_tx_deserialize(data + pos, len - pos, &tx_size);
        if (!tx) {
            ftc_block_free(block);
            return NULL;
        }

        if (!ftc_block_add_tx(block, tx)) {
            ftc_tx_free(tx);
            ftc_block_free(block);
            return NULL;
        }

        pos += tx_size;
    }

    return block;
}

char* ftc_block_to_hex(const ftc_block_t* block)
{
    size_t size = ftc_block_serialize(block, NULL, 0);
    if (size == 0) return NULL;

    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return NULL;

    if (ftc_block_serialize(block, data, size) == 0) {
        free(data);
        return NULL;
    }

    char* hex = (char*)malloc(size * 2 + 1);
    if (!hex) {
        free(data);
        return NULL;
    }

    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        hex[i * 2] = digits[(data[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    hex[size * 2] = '\0';

    free(data);
    return hex;
}

ftc_block_t* ftc_block_from_hex(const char* hex)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL;

    size_t data_len = hex_len / 2;
    uint8_t* data = (uint8_t*)malloc(data_len);
    if (!data) return NULL;

    for (size_t i = 0; i < data_len; i++) {
        int hi = hex[i * 2];
        int lo = hex[i * 2 + 1];

        if (hi >= '0' && hi <= '9') hi = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
        else { free(data); return NULL; }

        if (lo >= '0' && lo <= '9') lo = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
        else { free(data); return NULL; }

        data[i] = (uint8_t)((hi << 4) | lo);
    }

    ftc_block_t* block = ftc_block_deserialize(data, data_len);
    free(data);
    return block;
}

/*==============================================================================
 * VALIDATION
 *============================================================================*/

ftc_error_t ftc_block_validate_structure(const ftc_block_t* block)
{
    if (!block) return FTC_ERR_INVALID_PARAM;

    /* Must have at least coinbase */
    if (block->tx_count == 0) return FTC_ERR_INVALID_BLOCK;

    /* Check block size */
    size_t size = ftc_block_serialize(block, NULL, 0);
    if (size > FTC_MAX_BLOCK_SIZE) return FTC_ERR_INVALID_BLOCK;

    /* Verify Merkle root */
    ftc_hash256_t merkle;
    ftc_block_merkle_root(block, merkle);
    if (memcmp(merkle, block->header.merkle_root, 32) != 0) {
        return FTC_ERR_INVALID_BLOCK;
    }

    /* First transaction must be coinbase */
    ftc_tx_t* coinbase = ftc_block_coinbase(block);
    if (!ftc_tx_is_coinbase(coinbase)) {
        return FTC_ERR_INVALID_BLOCK;
    }

    /* Other transactions must not be coinbase */
    for (uint32_t i = 1; i < block->tx_count; i++) {
        if (ftc_tx_is_coinbase(block->transactions[i])) {
            return FTC_ERR_INVALID_BLOCK;
        }
    }

    return FTC_OK;
}

bool ftc_block_check_pow(const ftc_block_t* block)
{
    ftc_hash256_t hash, target;

    ftc_block_hash(block, hash);
    ftc_bits_to_target(block->header.bits, target);

    /* Hash must be <= target (comparing as big-endian) */
    return ftc_hash_compare(hash, target) <= 0;
}

size_t ftc_block_weight(const ftc_block_t* block)
{
    return ftc_block_serialize(block, NULL, 0);
}

/*==============================================================================
 * DIFFICULTY
 *============================================================================*/

void ftc_bits_to_target(uint32_t bits, ftc_hash256_t target)
{
    memset(target, 0, 32);

    uint32_t exp = (bits >> 24) & 0xff;
    uint32_t mantissa = bits & 0x007fffff;

    if (exp <= 3) {
        mantissa >>= 8 * (3 - exp);
        target[0] = (uint8_t)(mantissa & 0xff);
        target[1] = (uint8_t)((mantissa >> 8) & 0xff);
        target[2] = (uint8_t)((mantissa >> 16) & 0xff);
    } else {
        uint32_t offset = exp - 3;
        if (offset < 32) {
            target[offset] = (uint8_t)(mantissa & 0xff);
            if (offset + 1 < 32) target[offset + 1] = (uint8_t)((mantissa >> 8) & 0xff);
            if (offset + 2 < 32) target[offset + 2] = (uint8_t)((mantissa >> 16) & 0xff);
        }
    }
}

uint32_t ftc_target_to_bits(const ftc_hash256_t target)
{
    /* Find highest non-zero byte */
    int exp = 31;
    while (exp > 0 && target[exp] == 0) exp--;

    uint32_t mantissa;
    if (exp >= 2) {
        mantissa = ((uint32_t)target[exp] << 16) |
                   ((uint32_t)target[exp - 1] << 8) |
                   (uint32_t)target[exp - 2];
        exp += 1;
    } else if (exp == 1) {
        mantissa = ((uint32_t)target[1] << 16) |
                   ((uint32_t)target[0] << 8);
        exp = 2;
    } else {
        mantissa = (uint32_t)target[0] << 16;
        exp = 1;
    }

    /* Normalize: ensure mantissa doesn't have high bit set */
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exp++;
    }

    return ((uint32_t)exp << 24) | (mantissa & 0x007fffff);
}

double ftc_bits_to_difficulty(uint32_t bits)
{
    /* Difficulty = genesis_target / current_target */
    ftc_hash256_t target;
    ftc_bits_to_target(bits, target);

    /* Convert target to double (approximate) */
    double target_d = 0;
    for (int i = 31; i >= 0; i--) {
        target_d = target_d * 256.0 + target[i];
    }

    /* Genesis target (bits = 0x1e0fffff) */
    ftc_hash256_t genesis_target;
    ftc_bits_to_target(FTC_GENESIS_BITS, genesis_target);

    double genesis_d = 0;
    for (int i = 31; i >= 0; i--) {
        genesis_d = genesis_d * 256.0 + genesis_target[i];
    }

    if (target_d == 0) return 0;
    return genesis_d / target_d;
}

/*==============================================================================
 * GENESIS BLOCK
 *============================================================================*/

/* Pre-computed genesis block nonce (mined) */
#define GENESIS_NONCE_MAINNET   FTC_GENESIS_NONCE
#define GENESIS_NONCE_TESTNET   0

ftc_block_t* ftc_genesis_block(bool mainnet)
{
    ftc_block_t* block = ftc_block_new();
    if (!block) return NULL;

    /* Header */
    block->header.version = 1;
    ftc_hash_zero(block->header.prev_hash);  /* No previous block */
    block->header.timestamp = FTC_GENESIS_TIMESTAMP;
    block->header.bits = FTC_GENESIS_BITS;
    block->header.nonce = mainnet ? GENESIS_NONCE_MAINNET : GENESIS_NONCE_TESTNET;

    /* Create coinbase transaction */
    ftc_tx_t* coinbase = ftc_tx_create_coinbase(
        0,  /* Height 0 */
        FTC_INITIAL_REWARD,
        (const uint8_t*)FTC_GENESIS_MESSAGE,
        strlen(FTC_GENESIS_MESSAGE)
    );

    if (!coinbase) {
        ftc_block_free(block);
        return NULL;
    }

    if (!ftc_block_add_tx(block, coinbase)) {
        ftc_tx_free(coinbase);
        ftc_block_free(block);
        return NULL;
    }

    /* Calculate Merkle root */
    ftc_block_update_merkle(block);

    return block;
}

void ftc_genesis_hash(bool mainnet, ftc_hash256_t hash)
{
    ftc_block_t* genesis = ftc_genesis_block(mainnet);
    if (genesis) {
        ftc_block_hash(genesis, hash);
        ftc_block_free(genesis);
    } else {
        ftc_hash_zero(hash);
    }
}

bool ftc_block_is_genesis(const ftc_block_t* block, bool mainnet)
{
    if (!block) return false;

    ftc_hash256_t expected, actual;
    ftc_genesis_hash(mainnet, expected);
    ftc_block_hash(block, actual);

    return memcmp(expected, actual, 32) == 0;
}
