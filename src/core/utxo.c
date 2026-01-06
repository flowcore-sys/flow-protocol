/**
 * FTC UTXO Set Implementation
 *
 * In-memory UTXO set with hash table for fast lookups
 */

#include "utxo.h"
#include "tx.h"
#include "block.h"
#include "../crypto/keccak256.h"
#include <stdlib.h>
#include <string.h>

/*==============================================================================
 * HASH TABLE IMPLEMENTATION
 *============================================================================*/

#define UTXO_HASH_BUCKETS 65536
#define UTXO_BUCKET_MASK  (UTXO_HASH_BUCKETS - 1)

typedef struct utxo_entry {
    ftc_utxo_t utxo;
    struct utxo_entry* next;
} utxo_entry_t;

struct ftc_utxo_set {
    utxo_entry_t* buckets[UTXO_HASH_BUCKETS];
    size_t count;
    uint64_t total_value;
};

/* Hash function for outpoint */
static uint32_t hash_outpoint(const ftc_hash256_t txid, uint32_t vout)
{
    /* Simple hash: combine txid bytes with vout */
    uint32_t h = 0;
    for (int i = 0; i < 32; i++) {
        h = h * 31 + txid[i];
    }
    h = h * 31 + vout;
    return h & UTXO_BUCKET_MASK;
}

/*==============================================================================
 * UTXO SET OPERATIONS
 *============================================================================*/

ftc_utxo_set_t* ftc_utxo_set_new(void)
{
    ftc_utxo_set_t* set = (ftc_utxo_set_t*)calloc(1, sizeof(ftc_utxo_set_t));
    return set;
}

void ftc_utxo_set_free(ftc_utxo_set_t* set)
{
    if (!set) return;

    for (int i = 0; i < UTXO_HASH_BUCKETS; i++) {
        utxo_entry_t* entry = set->buckets[i];
        while (entry) {
            utxo_entry_t* next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(set);
}

bool ftc_utxo_set_add(ftc_utxo_set_t* set, const ftc_utxo_t* utxo)
{
    if (!set || !utxo) return false;

    /* Check if already exists */
    if (ftc_utxo_set_has(set, utxo->txid, utxo->vout)) {
        return false;
    }

    /* Create entry */
    utxo_entry_t* entry = (utxo_entry_t*)malloc(sizeof(utxo_entry_t));
    if (!entry) return false;

    memcpy(&entry->utxo, utxo, sizeof(ftc_utxo_t));
    entry->next = NULL;

    /* Insert into bucket */
    uint32_t bucket = hash_outpoint(utxo->txid, utxo->vout);

    entry->next = set->buckets[bucket];
    set->buckets[bucket] = entry;

    set->count++;
    set->total_value += utxo->value;

    return true;
}

ftc_utxo_t* ftc_utxo_set_remove(
    ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
)
{
    if (!set) return NULL;

    uint32_t bucket = hash_outpoint(txid, vout);
    utxo_entry_t* entry = set->buckets[bucket];
    utxo_entry_t* prev = NULL;

    while (entry) {
        if (memcmp(entry->utxo.txid, txid, 32) == 0 &&
            entry->utxo.vout == vout) {

            /* Remove from list */
            if (prev) {
                prev->next = entry->next;
            } else {
                set->buckets[bucket] = entry->next;
            }

            /* Create copy to return */
            ftc_utxo_t* result = ftc_utxo_copy(&entry->utxo);

            set->count--;
            set->total_value -= entry->utxo.value;

            free(entry);
            return result;
        }

        prev = entry;
        entry = entry->next;
    }

    return NULL;
}

const ftc_utxo_t* ftc_utxo_set_get(
    const ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
)
{
    if (!set) return NULL;

    uint32_t bucket = hash_outpoint(txid, vout);
    utxo_entry_t* entry = set->buckets[bucket];

    while (entry) {
        if (memcmp(entry->utxo.txid, txid, 32) == 0 &&
            entry->utxo.vout == vout) {
            return &entry->utxo;
        }
        entry = entry->next;
    }

    return NULL;
}

bool ftc_utxo_set_has(
    const ftc_utxo_set_t* set,
    const ftc_hash256_t txid,
    uint32_t vout
)
{
    return ftc_utxo_set_get(set, txid, vout) != NULL;
}

size_t ftc_utxo_set_count(const ftc_utxo_set_t* set)
{
    return set ? set->count : 0;
}

uint64_t ftc_utxo_set_total_value(const ftc_utxo_set_t* set)
{
    return set ? set->total_value : 0;
}

/*==============================================================================
 * ADDRESS LOOKUP
 *============================================================================*/

bool ftc_utxo_set_get_by_address(
    const ftc_utxo_set_t* set,
    const ftc_address_t address,
    ftc_utxo_t** out,
    size_t* count
)
{
    if (!set || !address || !out || !count) return false;

    *out = NULL;
    *count = 0;

    /* First pass: count matching UTXOs */
    size_t matches = 0;
    for (int i = 0; i < UTXO_HASH_BUCKETS; i++) {
        utxo_entry_t* entry = set->buckets[i];
        while (entry) {
            if (memcmp(entry->utxo.pubkey_hash, address, 20) == 0) {
                matches++;
            }
            entry = entry->next;
        }
    }

    if (matches == 0) {
        return true;  /* Success, but no matches */
    }

    /* Allocate array */
    *out = (ftc_utxo_t*)malloc(matches * sizeof(ftc_utxo_t));
    if (!*out) return false;

    /* Second pass: collect UTXOs */
    size_t idx = 0;
    for (int i = 0; i < UTXO_HASH_BUCKETS; i++) {
        utxo_entry_t* entry = set->buckets[i];
        while (entry) {
            if (memcmp(entry->utxo.pubkey_hash, address, 20) == 0) {
                memcpy(&(*out)[idx], &entry->utxo, sizeof(ftc_utxo_t));
                idx++;
            }
            entry = entry->next;
        }
    }

    *count = matches;
    return true;
}

uint64_t ftc_utxo_set_balance(
    const ftc_utxo_set_t* set,
    const ftc_address_t address
)
{
    if (!set || !address) return 0;

    uint64_t balance = 0;
    for (int i = 0; i < UTXO_HASH_BUCKETS; i++) {
        utxo_entry_t* entry = set->buckets[i];
        while (entry) {
            if (memcmp(entry->utxo.pubkey_hash, address, 20) == 0) {
                balance += entry->utxo.value;
            }
            entry = entry->next;
        }
    }

    return balance;
}

/*==============================================================================
 * BLOCK OPERATIONS
 *============================================================================*/

ftc_error_t ftc_utxo_set_connect_block(
    ftc_utxo_set_t* set,
    const ftc_block_t* block,
    uint32_t height
)
{
    if (!set || !block) return FTC_ERR_INVALID_PARAM;

    /* Process each transaction */
    for (uint32_t tx_idx = 0; tx_idx < block->tx_count; tx_idx++) {
        ftc_tx_t* tx = block->transactions[tx_idx];
        if (!tx) continue;

        /* Calculate txid */
        ftc_hash256_t txid;
        ftc_tx_hash(tx, txid);

        bool is_coinbase = ftc_tx_is_coinbase(tx);

        /* Remove spent UTXOs (skip for coinbase) */
        if (!is_coinbase) {
            for (uint32_t i = 0; i < tx->input_count; i++) {
                ftc_utxo_t* spent = ftc_utxo_set_remove(
                    set,
                    tx->inputs[i].prev_txid,
                    tx->inputs[i].vout
                );
                if (!spent) {
                    return FTC_ERR_INVALID_UTXO;  /* UTXO not found */
                }
                ftc_utxo_free(spent);
            }
        }

        /* Add new UTXOs */
        for (uint32_t i = 0; i < tx->output_count; i++) {
            /* Skip zero-value outputs */
            if (tx->outputs[i].value == 0) continue;

            ftc_utxo_t* utxo = ftc_utxo_new(
                txid,
                i,
                tx->outputs[i].value,
                tx->outputs[i].pubkey_hash,
                height,
                is_coinbase
            );

            if (!utxo) return FTC_ERR_OUT_OF_MEMORY;

            if (!ftc_utxo_set_add(set, utxo)) {
                ftc_utxo_free(utxo);
                return FTC_ERR_ALREADY_EXISTS;
            }

            ftc_utxo_free(utxo);
        }
    }

    return FTC_OK;
}

ftc_error_t ftc_utxo_set_disconnect_block(
    ftc_utxo_set_t* set,
    const ftc_block_t* block,
    uint32_t height
)
{
    if (!set || !block) return FTC_ERR_INVALID_PARAM;

    /* Process transactions in reverse order */
    for (int tx_idx = (int)block->tx_count - 1; tx_idx >= 0; tx_idx--) {
        ftc_tx_t* tx = block->transactions[tx_idx];
        if (!tx) continue;

        /* Calculate txid */
        ftc_hash256_t txid;
        ftc_tx_hash(tx, txid);

        /* Remove UTXOs created by this transaction */
        for (uint32_t i = 0; i < tx->output_count; i++) {
            ftc_utxo_t* removed = ftc_utxo_set_remove(set, txid, i);
            if (removed) ftc_utxo_free(removed);
        }

        /* Restore spent UTXOs (skip for coinbase) */
        /* Note: This requires having the original UTXO data,
         * which should be stored in block undo data in production */
    }

    return FTC_OK;
}

/*==============================================================================
 * UTXO CREATION
 *============================================================================*/

ftc_utxo_t* ftc_utxo_new(
    const ftc_hash256_t txid,
    uint32_t vout,
    uint64_t value,
    const ftc_address_t pubkey_hash,
    uint32_t height,
    bool coinbase
)
{
    ftc_utxo_t* utxo = (ftc_utxo_t*)calloc(1, sizeof(ftc_utxo_t));
    if (!utxo) return NULL;

    if (txid) memcpy(utxo->txid, txid, 32);
    utxo->vout = vout;
    utxo->value = value;
    if (pubkey_hash) memcpy(utxo->pubkey_hash, pubkey_hash, 20);
    utxo->height = height;
    utxo->coinbase = coinbase;

    return utxo;
}

void ftc_utxo_free(ftc_utxo_t* utxo)
{
    free(utxo);
}

ftc_utxo_t* ftc_utxo_copy(const ftc_utxo_t* utxo)
{
    if (!utxo) return NULL;

    ftc_utxo_t* copy = (ftc_utxo_t*)malloc(sizeof(ftc_utxo_t));
    if (!copy) return NULL;

    memcpy(copy, utxo, sizeof(ftc_utxo_t));
    return copy;
}

bool ftc_utxo_is_spendable(const ftc_utxo_t* utxo, uint32_t current_height)
{
    if (!utxo) return false;

    /* Coinbase outputs need to mature */
    if (utxo->coinbase) {
        if (current_height < utxo->height + FTC_COINBASE_MATURITY) {
            return false;
        }
    }

    return true;
}

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

size_t ftc_utxo_serialize(const ftc_utxo_t* utxo, uint8_t* out, size_t out_len)
{
    if (!utxo) return 0;

    /* Size: txid(32) + vout(4) + value(8) + pubkey_hash(20) + height(4) + coinbase(1) = 69 */
    size_t size = 69;

    if (!out) return size;
    if (out_len < size) return 0;

    size_t pos = 0;

    memcpy(out + pos, utxo->txid, 32);
    pos += 32;

    out[pos++] = (uint8_t)(utxo->vout & 0xff);
    out[pos++] = (uint8_t)((utxo->vout >> 8) & 0xff);
    out[pos++] = (uint8_t)((utxo->vout >> 16) & 0xff);
    out[pos++] = (uint8_t)((utxo->vout >> 24) & 0xff);

    for (int i = 0; i < 8; i++) {
        out[pos++] = (uint8_t)((utxo->value >> (i * 8)) & 0xff);
    }

    memcpy(out + pos, utxo->pubkey_hash, 20);
    pos += 20;

    out[pos++] = (uint8_t)(utxo->height & 0xff);
    out[pos++] = (uint8_t)((utxo->height >> 8) & 0xff);
    out[pos++] = (uint8_t)((utxo->height >> 16) & 0xff);
    out[pos++] = (uint8_t)((utxo->height >> 24) & 0xff);

    out[pos++] = utxo->coinbase ? 1 : 0;

    return pos;
}

ftc_utxo_t* ftc_utxo_deserialize(const uint8_t* data, size_t len)
{
    if (!data || len < 69) return NULL;

    ftc_utxo_t* utxo = (ftc_utxo_t*)calloc(1, sizeof(ftc_utxo_t));
    if (!utxo) return NULL;

    size_t pos = 0;

    memcpy(utxo->txid, data + pos, 32);
    pos += 32;

    utxo->vout = (uint32_t)data[pos] |
                 ((uint32_t)data[pos + 1] << 8) |
                 ((uint32_t)data[pos + 2] << 16) |
                 ((uint32_t)data[pos + 3] << 24);
    pos += 4;

    utxo->value = 0;
    for (int i = 0; i < 8; i++) {
        utxo->value |= ((uint64_t)data[pos++] << (i * 8));
    }

    memcpy(utxo->pubkey_hash, data + pos, 20);
    pos += 20;

    utxo->height = (uint32_t)data[pos] |
                   ((uint32_t)data[pos + 1] << 8) |
                   ((uint32_t)data[pos + 2] << 16) |
                   ((uint32_t)data[pos + 3] << 24);
    pos += 4;

    utxo->coinbase = data[pos] != 0;

    return utxo;
}

/*==============================================================================
 * OUTPOINT
 *============================================================================*/

void ftc_outpoint_key(const ftc_hash256_t txid, uint32_t vout, uint8_t out[36])
{
    memcpy(out, txid, 32);
    out[32] = (uint8_t)(vout & 0xff);
    out[33] = (uint8_t)((vout >> 8) & 0xff);
    out[34] = (uint8_t)((vout >> 16) & 0xff);
    out[35] = (uint8_t)((vout >> 24) & 0xff);
}

int ftc_outpoint_compare(const ftc_outpoint_t* a, const ftc_outpoint_t* b)
{
    int cmp = memcmp(a->txid, b->txid, 32);
    if (cmp != 0) return cmp;
    if (a->vout < b->vout) return -1;
    if (a->vout > b->vout) return 1;
    return 0;
}
