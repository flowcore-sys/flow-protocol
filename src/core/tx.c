/**
 * FTC Transaction Implementation
 */

#include "tx.h"
#include "block.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Cross-platform unused attribute */
#ifdef _MSC_VER
#define MAYBE_UNUSED
#else
#define MAYBE_UNUSED __attribute__((unused))
#endif

/*==============================================================================
 * COINBASE CONSTANTS
 *============================================================================*/

/* Coinbase input marker: all zeros */
MAYBE_UNUSED
static const ftc_hash256_t COINBASE_TXID = {0};
#define COINBASE_VOUT 0xffffffff

/*==============================================================================
 * TRANSACTION CREATION
 *============================================================================*/

ftc_tx_t* ftc_tx_new(void)
{
    ftc_tx_t* tx = (ftc_tx_t*)calloc(1, sizeof(ftc_tx_t));
    if (!tx) return NULL;

    tx->version = 1;
    return tx;
}

ftc_tx_t* ftc_tx_create_coinbase(
    uint32_t height,
    uint64_t reward,
    const uint8_t* script_data,
    size_t script_len
)
{
    ftc_tx_t* tx = ftc_tx_new();
    if (!tx) return NULL;

    /* Create coinbase input */
    tx->inputs = (ftc_txin_t*)calloc(1, sizeof(ftc_txin_t));
    if (!tx->inputs) {
        ftc_tx_free(tx);
        return NULL;
    }
    tx->input_count = 1;

    /* Set coinbase marker */
    memset(tx->inputs[0].prev_txid, 0, 32);
    tx->inputs[0].vout = COINBASE_VOUT;

    /* Encode height in signature field (BIP34 style) */
    uint8_t height_script[16];
    size_t height_len = 0;

    if (height <= 0xff) {
        height_script[0] = 1;
        height_script[1] = (uint8_t)height;
        height_len = 2;
    } else if (height <= 0xffff) {
        height_script[0] = 2;
        height_script[1] = (uint8_t)(height & 0xff);
        height_script[2] = (uint8_t)((height >> 8) & 0xff);
        height_len = 3;
    } else if (height <= 0xffffff) {
        height_script[0] = 3;
        height_script[1] = (uint8_t)(height & 0xff);
        height_script[2] = (uint8_t)((height >> 8) & 0xff);
        height_script[3] = (uint8_t)((height >> 16) & 0xff);
        height_len = 4;
    } else {
        height_script[0] = 4;
        height_script[1] = (uint8_t)(height & 0xff);
        height_script[2] = (uint8_t)((height >> 8) & 0xff);
        height_script[3] = (uint8_t)((height >> 16) & 0xff);
        height_script[4] = (uint8_t)((height >> 24) & 0xff);
        height_len = 5;
    }

    /* Store height in signature field */
    memset(tx->inputs[0].signature, 0, 64);
    memcpy(tx->inputs[0].signature, height_script, height_len);

    /* Store extra data in pubkey field */
    memset(tx->inputs[0].pubkey, 0, 32);
    if (script_data && script_len > 0) {
        size_t copy_len = script_len < 32 ? script_len : 32;
        memcpy(tx->inputs[0].pubkey, script_data, copy_len);
    }

    /* Create output - for now, use zero address (to be filled by miner) */
    tx->outputs = (ftc_txout_t*)calloc(1, sizeof(ftc_txout_t));
    if (!tx->outputs) {
        ftc_tx_free(tx);
        return NULL;
    }
    tx->output_count = 1;
    tx->outputs[0].value = reward;
    memset(tx->outputs[0].pubkey_hash, 0, 20);

    return tx;
}

void ftc_tx_free(ftc_tx_t* tx)
{
    if (!tx) return;

    if (tx->inputs) {
        free(tx->inputs);
    }
    if (tx->outputs) {
        free(tx->outputs);
    }

    free(tx);
}

ftc_tx_t* ftc_tx_copy(const ftc_tx_t* tx)
{
    if (!tx) return NULL;

    ftc_tx_t* copy = ftc_tx_new();
    if (!copy) return NULL;

    copy->version = tx->version;
    copy->locktime = tx->locktime;

    /* Copy inputs */
    if (tx->input_count > 0) {
        copy->inputs = (ftc_txin_t*)malloc(tx->input_count * sizeof(ftc_txin_t));
        if (!copy->inputs) {
            ftc_tx_free(copy);
            return NULL;
        }
        memcpy(copy->inputs, tx->inputs, tx->input_count * sizeof(ftc_txin_t));
        copy->input_count = tx->input_count;
    }

    /* Copy outputs */
    if (tx->output_count > 0) {
        copy->outputs = (ftc_txout_t*)malloc(tx->output_count * sizeof(ftc_txout_t));
        if (!copy->outputs) {
            ftc_tx_free(copy);
            return NULL;
        }
        memcpy(copy->outputs, tx->outputs, tx->output_count * sizeof(ftc_txout_t));
        copy->output_count = tx->output_count;
    }

    return copy;
}

/*==============================================================================
 * TRANSACTION BUILDING
 *============================================================================*/

bool ftc_tx_add_input(ftc_tx_t* tx, const ftc_hash256_t txid, uint32_t vout)
{
    if (!tx || !txid) return false;

    ftc_txin_t* new_inputs = (ftc_txin_t*)realloc(
        tx->inputs,
        (tx->input_count + 1) * sizeof(ftc_txin_t)
    );
    if (!new_inputs) return false;

    tx->inputs = new_inputs;
    memset(&tx->inputs[tx->input_count], 0, sizeof(ftc_txin_t));
    memcpy(tx->inputs[tx->input_count].prev_txid, txid, 32);
    tx->inputs[tx->input_count].vout = vout;
    tx->input_count++;

    return true;
}

bool ftc_tx_add_output(ftc_tx_t* tx, uint64_t value, const ftc_address_t address)
{
    if (!tx || !address) return false;

    ftc_txout_t* new_outputs = (ftc_txout_t*)realloc(
        tx->outputs,
        (tx->output_count + 1) * sizeof(ftc_txout_t)
    );
    if (!new_outputs) return false;

    tx->outputs = new_outputs;
    tx->outputs[tx->output_count].value = value;
    memcpy(tx->outputs[tx->output_count].pubkey_hash, address, 20);
    tx->output_count++;

    return true;
}

bool ftc_tx_sign_input(
    ftc_tx_t* tx,
    uint32_t input_idx,
    const ftc_privkey_t privkey,
    const ftc_pubkey_t pubkey
)
{
    if (!tx || input_idx >= tx->input_count) return false;

    /* Calculate sighash */
    ftc_hash256_t sighash;
    ftc_tx_sighash(tx, sighash);

    /* Sign */
    ftc_sign(
        privkey,
        pubkey,
        sighash,
        32,
        tx->inputs[input_idx].signature
    );

    /* Store public key */
    memcpy(tx->inputs[input_idx].pubkey, pubkey, 32);

    return true;
}

/*==============================================================================
 * TRANSACTION HASHING
 *============================================================================*/

void ftc_tx_hash(const ftc_tx_t* tx, ftc_hash256_t hash)
{
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    if (size == 0) {
        ftc_hash_zero(hash);
        return;
    }

    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) {
        ftc_hash_zero(hash);
        return;
    }

    ftc_tx_serialize(tx, data, size);
    ftc_keccak256(data, size, hash);
    free(data);
}

void ftc_tx_sighash(const ftc_tx_t* tx, ftc_hash256_t hash)
{
    if (!tx) {
        ftc_hash_zero(hash);
        return;
    }

    /* Create copy without signatures */
    ftc_tx_t* copy = ftc_tx_copy(tx);
    if (!copy) {
        ftc_hash_zero(hash);
        return;
    }

    /* Clear all signatures */
    for (uint32_t i = 0; i < copy->input_count; i++) {
        memset(copy->inputs[i].signature, 0, 64);
    }

    /* Hash */
    ftc_tx_hash(copy, hash);
    ftc_tx_free(copy);
}

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

/* Helper to write little-endian uint32 */
static void write_u32_le(uint8_t* out, uint32_t val)
{
    out[0] = (uint8_t)(val & 0xff);
    out[1] = (uint8_t)((val >> 8) & 0xff);
    out[2] = (uint8_t)((val >> 16) & 0xff);
    out[3] = (uint8_t)((val >> 24) & 0xff);
}

static uint32_t read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static void write_u64_le(uint8_t* out, uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)((val >> (i * 8)) & 0xff);
    }
}

static uint64_t read_u64_le(const uint8_t* data)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= ((uint64_t)data[i] << (i * 8));
    }
    return val;
}

size_t ftc_tx_serialize(const ftc_tx_t* tx, uint8_t* out, size_t out_len)
{
    if (!tx) return 0;

    /* Calculate size:
     * - version: 4
     * - input_count: varint
     * - inputs: each 32 + 4 + 64 + 32 = 132 bytes
     * - output_count: varint
     * - outputs: each 8 + 20 = 28 bytes
     * - locktime: 4
     */
    size_t size = 4;  /* version */
    size += ftc_varint_size(tx->input_count);
    size += tx->input_count * 132;
    size += ftc_varint_size(tx->output_count);
    size += tx->output_count * 28;
    size += 4;  /* locktime */

    if (!out) return size;
    if (out_len < size) return 0;

    size_t pos = 0;

    /* Version */
    write_u32_le(out + pos, tx->version);
    pos += 4;

    /* Input count */
    pos += ftc_varint_encode(tx->input_count, out + pos);

    /* Inputs */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        memcpy(out + pos, tx->inputs[i].prev_txid, 32);
        pos += 32;
        write_u32_le(out + pos, tx->inputs[i].vout);
        pos += 4;
        memcpy(out + pos, tx->inputs[i].signature, 64);
        pos += 64;
        memcpy(out + pos, tx->inputs[i].pubkey, 32);
        pos += 32;
    }

    /* Output count */
    pos += ftc_varint_encode(tx->output_count, out + pos);

    /* Outputs */
    for (uint32_t i = 0; i < tx->output_count; i++) {
        write_u64_le(out + pos, tx->outputs[i].value);
        pos += 8;
        memcpy(out + pos, tx->outputs[i].pubkey_hash, 20);
        pos += 20;
    }

    /* Locktime */
    write_u32_le(out + pos, tx->locktime);
    pos += 4;

    return pos;
}

ftc_tx_t* ftc_tx_deserialize(const uint8_t* data, size_t len, size_t* consumed)
{
    if (!data || len < 10) return NULL;

    ftc_tx_t* tx = ftc_tx_new();
    if (!tx) return NULL;

    size_t pos = 0;

    /* Version */
    if (pos + 4 > len) { ftc_tx_free(tx); return NULL; }
    tx->version = read_u32_le(data + pos);
    pos += 4;

    /* Input count */
    uint64_t input_count;
    size_t varint_len = ftc_varint_decode(data + pos, len - pos, &input_count);
    if (varint_len == 0 || input_count > 10000) { ftc_tx_free(tx); return NULL; }
    pos += varint_len;

    /* Inputs */
    if (input_count > 0) {
        tx->inputs = (ftc_txin_t*)calloc((size_t)input_count, sizeof(ftc_txin_t));
        if (!tx->inputs) { ftc_tx_free(tx); return NULL; }

        for (uint64_t i = 0; i < input_count; i++) {
            if (pos + 132 > len) { ftc_tx_free(tx); return NULL; }

            memcpy(tx->inputs[i].prev_txid, data + pos, 32);
            pos += 32;
            tx->inputs[i].vout = read_u32_le(data + pos);
            pos += 4;
            memcpy(tx->inputs[i].signature, data + pos, 64);
            pos += 64;
            memcpy(tx->inputs[i].pubkey, data + pos, 32);
            pos += 32;

            tx->input_count++;
        }
    }

    /* Output count */
    uint64_t output_count;
    varint_len = ftc_varint_decode(data + pos, len - pos, &output_count);
    if (varint_len == 0 || output_count > 10000) { ftc_tx_free(tx); return NULL; }
    pos += varint_len;

    /* Outputs */
    if (output_count > 0) {
        tx->outputs = (ftc_txout_t*)calloc((size_t)output_count, sizeof(ftc_txout_t));
        if (!tx->outputs) { ftc_tx_free(tx); return NULL; }

        for (uint64_t i = 0; i < output_count; i++) {
            if (pos + 28 > len) { ftc_tx_free(tx); return NULL; }

            tx->outputs[i].value = read_u64_le(data + pos);
            pos += 8;
            memcpy(tx->outputs[i].pubkey_hash, data + pos, 20);
            pos += 20;

            tx->output_count++;
        }
    }

    /* Locktime */
    if (pos + 4 > len) { ftc_tx_free(tx); return NULL; }
    tx->locktime = read_u32_le(data + pos);
    pos += 4;

    if (consumed) *consumed = pos;
    return tx;
}

char* ftc_tx_to_hex(const ftc_tx_t* tx)
{
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    if (size == 0) return NULL;

    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return NULL;

    if (ftc_tx_serialize(tx, data, size) == 0) {
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

ftc_tx_t* ftc_tx_from_hex(const char* hex)
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

    size_t consumed;
    ftc_tx_t* tx = ftc_tx_deserialize(data, data_len, &consumed);
    free(data);
    return tx;
}

/*==============================================================================
 * VALIDATION
 *============================================================================*/

ftc_error_t ftc_tx_validate_structure(const ftc_tx_t* tx)
{
    if (!tx) return FTC_ERR_INVALID_PARAM;

    /* Must have at least one input and output */
    if (tx->input_count == 0) return FTC_ERR_INVALID_TX;
    if (tx->output_count == 0) return FTC_ERR_INVALID_TX;

    /* Check for overflow in outputs */
    uint64_t total_output = 0;
    for (uint32_t i = 0; i < tx->output_count; i++) {
        if (tx->outputs[i].value > FTC_MAX_SUPPLY) {
            return FTC_ERR_INVALID_TX;
        }
        if (total_output + tx->outputs[i].value < total_output) {
            return FTC_ERR_INVALID_TX;  /* Overflow */
        }
        total_output += tx->outputs[i].value;
    }

    if (total_output > FTC_MAX_SUPPLY) {
        return FTC_ERR_INVALID_TX;
    }

    /* Check transaction size */
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    if (size > FTC_MAX_TX_SIZE) {
        return FTC_ERR_INVALID_TX;
    }

    return FTC_OK;
}

bool ftc_tx_verify_input(const ftc_tx_t* tx, uint32_t input_idx)
{
    if (!tx || input_idx >= tx->input_count) return false;

    /* Coinbase inputs don't need signature verification */
    if (ftc_tx_is_coinbase(tx)) return true;

    /* Calculate sighash */
    ftc_hash256_t sighash;
    ftc_tx_sighash(tx, sighash);

    /* Verify signature */
    return ftc_verify(
        tx->inputs[input_idx].pubkey,
        sighash,
        32,
        tx->inputs[input_idx].signature
    );
}

bool ftc_tx_is_coinbase(const ftc_tx_t* tx)
{
    if (!tx || tx->input_count != 1) return false;

    /* Check for coinbase marker */
    bool zero_txid = true;
    for (int i = 0; i < 32; i++) {
        if (tx->inputs[0].prev_txid[i] != 0) {
            zero_txid = false;
            break;
        }
    }

    return zero_txid && tx->inputs[0].vout == COINBASE_VOUT;
}

uint64_t ftc_tx_input_value(const ftc_tx_t* tx, ftc_utxo_lookup_fn lookup)
{
    if (!tx || !lookup) return 0;

    uint64_t total = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
        uint64_t value = lookup(tx->inputs[i].prev_txid, tx->inputs[i].vout);
        if (value == 0) return 0;  /* UTXO not found */
        total += value;
    }
    return total;
}

uint64_t ftc_tx_output_value(const ftc_tx_t* tx)
{
    if (!tx) return 0;

    uint64_t total = 0;
    for (uint32_t i = 0; i < tx->output_count; i++) {
        total += tx->outputs[i].value;
    }
    return total;
}

int64_t ftc_tx_fee(const ftc_tx_t* tx, ftc_utxo_lookup_fn lookup)
{
    if (ftc_tx_is_coinbase(tx)) return 0;

    uint64_t input = ftc_tx_input_value(tx, lookup);
    uint64_t output = ftc_tx_output_value(tx);

    if (input < output) return -1;  /* Invalid */
    return (int64_t)(input - output);
}

size_t ftc_tx_vsize(const ftc_tx_t* tx)
{
    return ftc_tx_serialize(tx, NULL, 0);
}

/*==============================================================================
 * TXIN/TXOUT HELPERS
 *============================================================================*/

ftc_txin_t* ftc_txin_new(const ftc_hash256_t prev_txid, uint32_t vout)
{
    ftc_txin_t* txin = (ftc_txin_t*)calloc(1, sizeof(ftc_txin_t));
    if (!txin) return NULL;

    if (prev_txid) {
        memcpy(txin->prev_txid, prev_txid, 32);
    }
    txin->vout = vout;

    return txin;
}

ftc_txout_t* ftc_txout_new(uint64_t value, const ftc_address_t pubkey_hash)
{
    ftc_txout_t* txout = (ftc_txout_t*)calloc(1, sizeof(ftc_txout_t));
    if (!txout) return NULL;

    txout->value = value;
    if (pubkey_hash) {
        memcpy(txout->pubkey_hash, pubkey_hash, 20);
    }

    return txout;
}

void ftc_txin_free(ftc_txin_t* txin)
{
    free(txin);
}

void ftc_txout_free(ftc_txout_t* txout)
{
    free(txout);
}

bool ftc_txin_is_coinbase(const ftc_txin_t* txin)
{
    if (!txin) return false;

    bool zero_txid = true;
    for (int i = 0; i < 32; i++) {
        if (txin->prev_txid[i] != 0) {
            zero_txid = false;
            break;
        }
    }

    return zero_txid && txin->vout == COINBASE_VOUT;
}
