/**
 * FTC Mempool Implementation
 */

#include "mempool.h"
#include "block.h"
#include "consensus.h"
#include "../crypto/keccak256.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*==============================================================================
 * MEMPOOL STRUCTURE
 *============================================================================*/

#define MEMPOOL_HASH_BUCKETS 4096
#define MEMPOOL_BUCKET_MASK  (MEMPOOL_HASH_BUCKETS - 1)

typedef struct mempool_node {
    ftc_mempool_entry_t entry;
    struct mempool_node* hash_next;     /* Hash table chain */
    struct mempool_node* fee_prev;      /* Fee-sorted doubly-linked list */
    struct mempool_node* fee_next;
} mempool_node_t;

/* Spent outpoint tracker */
typedef struct spent_outpoint {
    ftc_hash256_t txid;
    uint32_t vout;
    ftc_hash256_t spending_txid;
    struct spent_outpoint* next;
} spent_outpoint_t;

struct ftc_mempool {
    mempool_node_t* hash_buckets[MEMPOOL_HASH_BUCKETS];
    mempool_node_t* fee_head;           /* Highest fee rate first */
    mempool_node_t* fee_tail;           /* Lowest fee rate */
    spent_outpoint_t* spent_buckets[MEMPOOL_HASH_BUCKETS];
    size_t count;
    size_t total_size;
    size_t max_size;
    uint64_t total_fees;
};

/*==============================================================================
 * HASH FUNCTIONS
 *============================================================================*/

static uint32_t hash_txid(const ftc_hash256_t txid)
{
    uint32_t h = 0;
    for (int i = 0; i < 32; i++) {
        h = h * 31 + txid[i];
    }
    return h & MEMPOOL_BUCKET_MASK;
}

static uint32_t hash_outpoint(const ftc_hash256_t txid, uint32_t vout)
{
    uint32_t h = 0;
    for (int i = 0; i < 32; i++) {
        h = h * 31 + txid[i];
    }
    h = h * 31 + vout;
    return h & MEMPOOL_BUCKET_MASK;
}

/*==============================================================================
 * MEMPOOL CREATION
 *============================================================================*/

ftc_mempool_t* ftc_mempool_new(size_t max_size)
{
    ftc_mempool_t* mempool = (ftc_mempool_t*)calloc(1, sizeof(ftc_mempool_t));
    if (!mempool) return NULL;

    mempool->max_size = max_size > 0 ? max_size : (300 * 1024 * 1024);  /* Default 300MB */

    return mempool;
}

void ftc_mempool_free(ftc_mempool_t* mempool)
{
    if (!mempool) return;

    ftc_mempool_clear(mempool);
    free(mempool);
}

/*==============================================================================
 * INTERNAL HELPERS
 *============================================================================*/

static mempool_node_t* find_node(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
)
{
    uint32_t bucket = hash_txid(txid);
    mempool_node_t* node = mempool->hash_buckets[bucket];

    while (node) {
        if (memcmp(node->entry.txid, txid, 32) == 0) {
            return node;
        }
        node = node->hash_next;
    }

    return NULL;
}

static void mark_inputs_spent(
    ftc_mempool_t* mempool,
    const ftc_tx_t* tx,
    const ftc_hash256_t spending_txid
)
{
    for (uint32_t i = 0; i < tx->input_count; i++) {
        spent_outpoint_t* spent = (spent_outpoint_t*)malloc(sizeof(spent_outpoint_t));
        if (!spent) continue;

        memcpy(spent->txid, tx->inputs[i].prev_txid, 32);
        spent->vout = tx->inputs[i].vout;
        memcpy(spent->spending_txid, spending_txid, 32);

        uint32_t bucket = hash_outpoint(spent->txid, spent->vout);
        spent->next = mempool->spent_buckets[bucket];
        mempool->spent_buckets[bucket] = spent;
    }
}

static void unmark_inputs_spent(
    ftc_mempool_t* mempool,
    const ftc_tx_t* tx
)
{
    for (uint32_t i = 0; i < tx->input_count; i++) {
        uint32_t bucket = hash_outpoint(tx->inputs[i].prev_txid, tx->inputs[i].vout);

        spent_outpoint_t* prev = NULL;
        spent_outpoint_t* spent = mempool->spent_buckets[bucket];

        while (spent) {
            if (memcmp(spent->txid, tx->inputs[i].prev_txid, 32) == 0 &&
                spent->vout == tx->inputs[i].vout) {

                if (prev) {
                    prev->next = spent->next;
                } else {
                    mempool->spent_buckets[bucket] = spent->next;
                }

                free(spent);
                break;
            }

            prev = spent;
            spent = spent->next;
        }
    }
}

static void insert_by_fee(ftc_mempool_t* mempool, mempool_node_t* node)
{
    /* Insert into fee-sorted list (highest first) */
    if (!mempool->fee_head) {
        mempool->fee_head = node;
        mempool->fee_tail = node;
        node->fee_prev = NULL;
        node->fee_next = NULL;
        return;
    }

    /* Find insertion point */
    mempool_node_t* current = mempool->fee_head;
    while (current && current->entry.fee_rate >= node->entry.fee_rate) {
        current = current->fee_next;
    }

    if (!current) {
        /* Insert at tail */
        node->fee_prev = mempool->fee_tail;
        node->fee_next = NULL;
        mempool->fee_tail->fee_next = node;
        mempool->fee_tail = node;
    } else if (current == mempool->fee_head) {
        /* Insert at head */
        node->fee_prev = NULL;
        node->fee_next = mempool->fee_head;
        mempool->fee_head->fee_prev = node;
        mempool->fee_head = node;
    } else {
        /* Insert in middle */
        node->fee_prev = current->fee_prev;
        node->fee_next = current;
        current->fee_prev->fee_next = node;
        current->fee_prev = node;
    }
}

static void remove_from_fee_list(ftc_mempool_t* mempool, mempool_node_t* node)
{
    if (node->fee_prev) {
        node->fee_prev->fee_next = node->fee_next;
    } else {
        mempool->fee_head = node->fee_next;
    }

    if (node->fee_next) {
        node->fee_next->fee_prev = node->fee_prev;
    } else {
        mempool->fee_tail = node->fee_prev;
    }
}

/*==============================================================================
 * TRANSACTION MANAGEMENT
 *============================================================================*/

ftc_error_t ftc_mempool_add(
    ftc_mempool_t* mempool,
    ftc_tx_t* tx,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
)
{
    if (!mempool || !tx) return FTC_ERR_INVALID_PARAM;

    /* Calculate txid */
    ftc_hash256_t txid;
    ftc_tx_hash(tx, txid);

    /* Check if already in mempool */
    if (ftc_mempool_has(mempool, txid)) {
        ftc_tx_free(tx);
        return FTC_ERR_ALREADY_EXISTS;
    }

    /* Validate transaction structure */
    ftc_error_t err = ftc_tx_validate_structure(tx);
    if (err != FTC_OK) {
        ftc_tx_free(tx);
        return err;
    }

    /* Check for double-spend within mempool */
    if (ftc_mempool_check_double_spend(mempool, tx)) {
        ftc_tx_free(tx);
        return FTC_ERR_DOUBLE_SPEND;
    }

    /* Verify signatures */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        if (!ftc_tx_verify_input(tx, i)) {
            ftc_tx_free(tx);
            return FTC_ERR_INVALID_SIGNATURE;
        }
    }

    /* Calculate fee (requires UTXO set) */
    uint64_t input_value = 0;
    if (utxo_set) {
        for (uint32_t i = 0; i < tx->input_count; i++) {
            const ftc_utxo_t* utxo = ftc_utxo_set_get(
                utxo_set,
                tx->inputs[i].prev_txid,
                tx->inputs[i].vout
            );
            if (!utxo) {
                /* Maybe it's in the mempool */
                const ftc_mempool_entry_t* parent = ftc_mempool_get_entry(
                    mempool,
                    tx->inputs[i].prev_txid
                );
                if (!parent || tx->inputs[i].vout >= parent->tx->output_count) {
                    ftc_tx_free(tx);
                    return FTC_ERR_INVALID_UTXO;
                }
                input_value += parent->tx->outputs[tx->inputs[i].vout].value;
            } else {
                input_value += utxo->value;
            }
        }
    }

    uint64_t output_value = ftc_tx_output_value(tx);
    if (input_value < output_value) {
        ftc_tx_free(tx);
        return FTC_ERR_INSUFFICIENT_FUNDS;
    }

    uint64_t fee = input_value - output_value;
    size_t tx_size = ftc_tx_serialize(tx, NULL, 0);

    /* Check minimum fee */
    if (fee < FTC_MIN_TX_FEE && tx_size > 100) {
        ftc_tx_free(tx);
        return FTC_ERR_INVALID_TX;
    }

    /* Evict if needed */
    if (mempool->total_size + tx_size > mempool->max_size) {
        if (!ftc_mempool_evict(mempool, tx_size)) {
            ftc_tx_free(tx);
            return FTC_ERR_OUT_OF_MEMORY;
        }
    }

    /* Create entry */
    mempool_node_t* node = (mempool_node_t*)calloc(1, sizeof(mempool_node_t));
    if (!node) {
        ftc_tx_free(tx);
        return FTC_ERR_OUT_OF_MEMORY;
    }

    node->entry.tx = tx;
    memcpy(node->entry.txid, txid, 32);
    node->entry.fee = fee;
    node->entry.size = tx_size;
    node->entry.fee_rate = (double)fee / tx_size;
    node->entry.time = (uint64_t)time(NULL);
    node->entry.height = height;

    /* Add to hash table */
    uint32_t bucket = hash_txid(txid);
    node->hash_next = mempool->hash_buckets[bucket];
    mempool->hash_buckets[bucket] = node;

    /* Add to fee-sorted list */
    insert_by_fee(mempool, node);

    /* Mark inputs as spent */
    mark_inputs_spent(mempool, tx, txid);

    /* Update stats */
    mempool->count++;
    mempool->total_size += tx_size;
    mempool->total_fees += fee;

    return FTC_OK;
}

ftc_tx_t* ftc_mempool_remove(
    ftc_mempool_t* mempool,
    const ftc_hash256_t txid
)
{
    if (!mempool) return NULL;

    uint32_t bucket = hash_txid(txid);
    mempool_node_t* prev = NULL;
    mempool_node_t* node = mempool->hash_buckets[bucket];

    while (node) {
        if (memcmp(node->entry.txid, txid, 32) == 0) {
            /* Remove from hash table */
            if (prev) {
                prev->hash_next = node->hash_next;
            } else {
                mempool->hash_buckets[bucket] = node->hash_next;
            }

            /* Remove from fee list */
            remove_from_fee_list(mempool, node);

            /* Unmark inputs */
            unmark_inputs_spent(mempool, node->entry.tx);

            /* Update stats */
            mempool->count--;
            mempool->total_size -= node->entry.size;
            mempool->total_fees -= node->entry.fee;

            ftc_tx_t* tx = node->entry.tx;
            free(node);
            return tx;
        }

        prev = node;
        node = node->hash_next;
    }

    return NULL;
}

const ftc_tx_t* ftc_mempool_get(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
)
{
    mempool_node_t* node = find_node(mempool, txid);
    return node ? node->entry.tx : NULL;
}

bool ftc_mempool_has(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
)
{
    return find_node(mempool, txid) != NULL;
}

const ftc_mempool_entry_t* ftc_mempool_get_entry(
    const ftc_mempool_t* mempool,
    const ftc_hash256_t txid
)
{
    mempool_node_t* node = find_node(mempool, txid);
    return node ? &node->entry : NULL;
}

/*==============================================================================
 * BLOCK OPERATIONS
 *============================================================================*/

void ftc_mempool_remove_block(
    ftc_mempool_t* mempool,
    const ftc_block_t* block
)
{
    if (!mempool || !block) return;

    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_hash256_t txid;
        ftc_tx_hash(block->transactions[i], txid);

        ftc_tx_t* removed = ftc_mempool_remove(mempool, txid);
        if (removed) {
            ftc_tx_free(removed);
        }
    }
}

void ftc_mempool_add_block(
    ftc_mempool_t* mempool,
    const ftc_block_t* block,
    const ftc_utxo_set_t* utxo_set,
    uint32_t height
)
{
    if (!mempool || !block) return;

    /* Add back transactions (skip coinbase) */
    for (uint32_t i = 1; i < block->tx_count; i++) {
        ftc_tx_t* tx = ftc_tx_copy(block->transactions[i]);
        if (tx) {
            ftc_mempool_add(mempool, tx, utxo_set, height);
        }
    }
}

/*==============================================================================
 * TRANSACTION SELECTION
 *============================================================================*/

bool ftc_mempool_select_transactions(
    const ftc_mempool_t* mempool,
    size_t max_size,
    ftc_tx_t*** out_txs,
    size_t* out_count,
    uint64_t* out_fees
)
{
    if (!mempool || !out_txs || !out_count || !out_fees) return false;

    *out_txs = NULL;
    *out_count = 0;
    *out_fees = 0;

    if (mempool->count == 0) return true;

    /* Allocate maximum possible array */
    ftc_tx_t** txs = (ftc_tx_t**)malloc(mempool->count * sizeof(ftc_tx_t*));
    if (!txs) return false;

    size_t total_size = 0;
    size_t count = 0;
    uint64_t total_fees = 0;

    /* Walk fee-sorted list from highest to lowest */
    mempool_node_t* node = mempool->fee_head;
    while (node && total_size < max_size) {
        if (total_size + node->entry.size <= max_size) {
            txs[count++] = node->entry.tx;
            total_size += node->entry.size;
            total_fees += node->entry.fee;
        }
        node = node->fee_next;
    }

    /* Shrink array */
    if (count < mempool->count) {
        ftc_tx_t** shrunk = (ftc_tx_t**)realloc(txs, count * sizeof(ftc_tx_t*));
        if (shrunk) txs = shrunk;
    }

    *out_txs = txs;
    *out_count = count;
    *out_fees = total_fees;

    return true;
}

/*==============================================================================
 * MEMPOOL STATUS
 *============================================================================*/

size_t ftc_mempool_count(const ftc_mempool_t* mempool)
{
    return mempool ? mempool->count : 0;
}

size_t ftc_mempool_size(const ftc_mempool_t* mempool)
{
    return mempool ? mempool->total_size : 0;
}

void ftc_mempool_info(const ftc_mempool_t* mempool, ftc_mempool_info_t* info)
{
    if (!info) return;

    memset(info, 0, sizeof(ftc_mempool_info_t));

    if (mempool) {
        info->tx_count = mempool->count;
        info->total_size = mempool->total_size;
        info->max_size = mempool->max_size;
        info->total_fees = mempool->total_fees;

        /* Get minimum fee rate from tail */
        if (mempool->fee_tail) {
            info->min_fee_rate = mempool->fee_tail->entry.fee_rate;
        }
    }
}

/*==============================================================================
 * DOUBLE SPEND DETECTION
 *============================================================================*/

bool ftc_mempool_check_double_spend(
    const ftc_mempool_t* mempool,
    const ftc_tx_t* tx
)
{
    if (!mempool || !tx) return false;

    for (uint32_t i = 0; i < tx->input_count; i++) {
        uint32_t bucket = hash_outpoint(tx->inputs[i].prev_txid, tx->inputs[i].vout);
        spent_outpoint_t* spent = mempool->spent_buckets[bucket];

        while (spent) {
            if (memcmp(spent->txid, tx->inputs[i].prev_txid, 32) == 0 &&
                spent->vout == tx->inputs[i].vout) {
                return true;  /* Double spend detected */
            }
            spent = spent->next;
        }
    }

    return false;
}

/*==============================================================================
 * EVICTION
 *============================================================================*/

bool ftc_mempool_evict(ftc_mempool_t* mempool, size_t bytes)
{
    if (!mempool) return false;

    size_t freed = 0;

    while (mempool->fee_tail && freed < bytes) {
        mempool_node_t* node = mempool->fee_tail;
        ftc_hash256_t txid;
        memcpy(txid, node->entry.txid, 32);

        freed += node->entry.size;

        ftc_tx_t* tx = ftc_mempool_remove(mempool, txid);
        if (tx) {
            ftc_tx_free(tx);
        }
    }

    return freed >= bytes;
}

void ftc_mempool_clear(ftc_mempool_t* mempool)
{
    if (!mempool) return;

    /* Free all nodes */
    for (int i = 0; i < MEMPOOL_HASH_BUCKETS; i++) {
        mempool_node_t* node = mempool->hash_buckets[i];
        while (node) {
            mempool_node_t* next = node->hash_next;
            ftc_tx_free(node->entry.tx);
            free(node);
            node = next;
        }
        mempool->hash_buckets[i] = NULL;
    }

    /* Free spent trackers */
    for (int i = 0; i < MEMPOOL_HASH_BUCKETS; i++) {
        spent_outpoint_t* spent = mempool->spent_buckets[i];
        while (spent) {
            spent_outpoint_t* next = spent->next;
            free(spent);
            spent = next;
        }
        mempool->spent_buckets[i] = NULL;
    }

    mempool->fee_head = NULL;
    mempool->fee_tail = NULL;
    mempool->count = 0;
    mempool->total_size = 0;
    mempool->total_fees = 0;
}
