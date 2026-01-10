/**
 * FTC Full Node Implementation
 */

#include "full_node.h"
#include "../src/crypto/keccak256.h"
#include "../src/crypto/keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

/* Silent logging - no output */
#define log_node(...) ((void)0)

/*==============================================================================
 * GLOBALS
 *============================================================================*/

static volatile bool g_shutdown_requested = false;

static void signal_handler(int sig)
{
    (void)sig;
    g_shutdown_requested = true;
}

/*==============================================================================
 * CHAIN MANAGEMENT
 *============================================================================*/

static ftc_chain_t* chain_new(void)
{
    ftc_chain_t* chain = (ftc_chain_t*)calloc(1, sizeof(ftc_chain_t));
    if (!chain) return NULL;

    chain->block_capacity = 1024;
    chain->blocks = (ftc_block_t**)calloc(chain->block_capacity, sizeof(ftc_block_t*));
    if (!chain->blocks) {
        free(chain);
        return NULL;
    }

    /* hash_index is already zeroed by calloc */

    FTC_MUTEX_INIT(chain->mutex);

    return chain;
}

/* Clone a block by serializing and deserializing */
static ftc_block_t* clone_block(ftc_block_t* block)
{
    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return NULL;
    ftc_block_serialize(block, data, size);
    ftc_block_t* copy = ftc_block_deserialize(data, size);
    free(data);
    return copy;
}

/* Expand block array capacity */
static bool expand_block_array(ftc_chain_t* chain)
{
    int new_cap = chain->block_capacity * 2;
    ftc_block_t** new_blocks = (ftc_block_t**)realloc(chain->blocks, new_cap * sizeof(ftc_block_t*));
    if (!new_blocks) return false;
    chain->blocks = new_blocks;
    chain->block_capacity = new_cap;
    return true;
}

/* Hash index helper functions for O(1) block lookups */
static inline uint32_t hash_index_slot(const ftc_hash256_t hash)
{
    /* Use first 4 bytes of hash as index, masked to table size */
    uint32_t slot = (hash[0] | (hash[1] << 8) | (hash[2] << 16) | (hash[3] << 24));
    return slot & (FTC_HASH_INDEX_SIZE - 1);
}

static void hash_index_add(ftc_chain_t* chain, const ftc_hash256_t hash, int block_index)
{
    uint32_t slot = hash_index_slot(hash);

    ftc_hash_entry_t* entry = (ftc_hash_entry_t*)malloc(sizeof(ftc_hash_entry_t));
    if (!entry) return;

    memcpy(entry->hash, hash, 32);
    entry->block_index = block_index;
    entry->next = chain->hash_index[slot];
    chain->hash_index[slot] = entry;
}

static int hash_index_find(ftc_chain_t* chain, const ftc_hash256_t hash)
{
    uint32_t slot = hash_index_slot(hash);

    ftc_hash_entry_t* entry = chain->hash_index[slot];
    while (entry) {
        if (memcmp(entry->hash, hash, 32) == 0) {
            return entry->block_index;
        }
        entry = entry->next;
    }
    return -1;  /* Not found */
}

static void hash_index_free(ftc_chain_t* chain)
{
    for (int i = 0; i < FTC_HASH_INDEX_SIZE; i++) {
        ftc_hash_entry_t* entry = chain->hash_index[i];
        while (entry) {
            ftc_hash_entry_t* next = entry->next;
            free(entry);
            entry = next;
        }
    }
}

static void chain_free(ftc_chain_t* chain)
{
    if (!chain) return;

    FTC_MUTEX_DESTROY(chain->mutex);

    /* Free hash index */
    hash_index_free(chain);

    for (int i = 0; i < chain->block_count; i++) {
        if (chain->blocks[i]) {
            ftc_block_free(chain->blocks[i]);
        }
    }
    free(chain->blocks);

    if (chain->genesis) {
        ftc_block_free(chain->genesis);
    }

    free(chain);
}

/*==============================================================================
 * BLOCKCHAIN PERSISTENCE
 *============================================================================*/

#define FTC_BLOCKS_MAGIC 0x42435446  /* "FTCB" */
#define FTC_BLOCKS_VERSION 1

static bool ftc_chain_save(ftc_chain_t* chain, const char* path)
{
    FTC_MUTEX_LOCK(chain->mutex);

    uint32_t count = (uint32_t)chain->block_count;

    /* Don't overwrite file if we have fewer blocks than originally loaded */
    if (chain->loaded_block_count > 0 && count < chain->loaded_block_count) {
        log_node("[NODE] Skipping save: have %u blocks but file had %u\n",
               count, chain->loaded_block_count);
        FTC_MUTEX_UNLOCK(chain->mutex);
        return false;
    }

    /* Write to temp file first for atomic save */
    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        log_node("[NODE] Failed to open %s for writing\n", temp_path);
        FTC_MUTEX_UNLOCK(chain->mutex);
        return false;
    }

    /* Write header */
    uint32_t magic = FTC_BLOCKS_MAGIC;
    uint32_t version = FTC_BLOCKS_VERSION;

    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);
    fwrite(&count, 4, 1, f);

    /* Write blocks (skip genesis at index 0, it's regenerated) */
    for (int i = 1; i < chain->block_count; i++) {
        ftc_block_t* block = chain->blocks[i];
        if (!block) continue;

        size_t block_size = ftc_block_serialize(block, NULL, 0);
        uint8_t* block_data = (uint8_t*)malloc(block_size);
        if (!block_data) {
            FTC_MUTEX_UNLOCK(chain->mutex);
            fclose(f);
            remove(temp_path);
            return false;
        }

        ftc_block_serialize(block, block_data, block_size);

        uint32_t size32 = (uint32_t)block_size;
        fwrite(&size32, 4, 1, f);
        fwrite(block_data, 1, block_size, f);

        free(block_data);
    }

    /* Flush to disk before rename */
    fflush(f);
#ifdef _WIN32
    _commit(_fileno(f));  /* Force write to disk on Windows */
#else
    fsync(fileno(f));     /* Force write to disk on Linux */
#endif
    fclose(f);

    /* Atomic rename: remove old file and rename temp */
    remove(path);
    if (rename(temp_path, path) != 0) {
        log_node("[NODE] Failed to rename %s to %s\n", temp_path, path);
        return false;
    }

    /* Update loaded count to allow future saves */
    chain->loaded_block_count = count;

    FTC_MUTEX_UNLOCK(chain->mutex);

    return true;
}

static int ftc_chain_load(ftc_node_t* node, const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f) {
        /* No saved blockchain - start fresh */
        return 0;
    }

    /* Read header */
    uint32_t magic, version, count;
    if (fread(&magic, 4, 1, f) != 1 || magic != FTC_BLOCKS_MAGIC) {
        log_node("[NODE] Invalid blocks.dat magic\n");
        fclose(f);
        return -1;
    }

    if (fread(&version, 4, 1, f) != 1 || version != FTC_BLOCKS_VERSION) {
        log_node("[NODE] Unsupported blocks.dat version\n");
        fclose(f);
        return -1;
    }

    if (fread(&count, 4, 1, f) != 1) {
        log_node("[NODE] Failed to read block count\n");
        fclose(f);
        return -1;
    }

    /* Loading blocks silently for clean dashboard */

    int loaded = 0;

    /* Read blocks (count includes genesis which we skip) */
    for (uint32_t i = 1; i < count; i++) {
        uint32_t size32;
        if (fread(&size32, 4, 1, f) != 1) {
            log_node("[NODE] Failed to read block %u size\n", i);
            break;
        }

        uint8_t* block_data = (uint8_t*)malloc(size32);
        if (!block_data) {
            log_node("[NODE] Out of memory loading block %u\n", i);
            break;
        }

        if (fread(block_data, 1, size32, f) != size32) {
            log_node("[NODE] Failed to read block %u data\n", i);
            free(block_data);
            break;
        }

        ftc_block_t* block = ftc_block_deserialize(block_data, size32);
        free(block_data);

        if (!block) {
            log_node("[NODE] Failed to deserialize block %u\n", i);
            break;
        }

        /* Add block to chain */
        bool skip_validation = node->config.recovery_mode || (i <= FTC_CHECKPOINT_HEIGHT);
        if (skip_validation) {
            /* Checkpoint/recovery mode: add blocks directly without prev_hash validation */
            ftc_chain_t* chain = node->chain;

            /* Expand if needed */
            if (chain->block_count >= chain->block_capacity) {
                expand_block_array(chain);
            }

            /* Clone block for storage */
            ftc_block_t* block_copy = clone_block(block);
            if (block_copy) {
                ftc_hash256_t block_hash;
                ftc_block_hash(block, block_hash);

                chain->blocks[chain->block_count++] = block_copy;
                chain->best_height++;
                memcpy(chain->best_hash, block_hash, 32);
                hash_index_add(chain, block_hash, chain->block_count - 1);

                /* Update UTXO set */
                for (uint32_t t = 0; t < block->tx_count; t++) {
                    ftc_tx_t* tx = block->txs[t];
                    ftc_hash256_t txid;
                    ftc_tx_hash(tx, txid);

                    /* Remove spent UTXOs */
                    if (!ftc_tx_is_coinbase(tx)) {
                        for (uint32_t j = 0; j < tx->input_count; j++) {
                            ftc_utxo_t* spent = ftc_utxo_set_remove(node->utxo_set, tx->inputs[j].prev_txid, tx->inputs[j].vout);
                            if (spent) ftc_utxo_free(spent);
                        }
                    }

                    /* Add new UTXOs */
                    for (uint32_t j = 0; j < tx->output_count; j++) {
                        ftc_utxo_t utxo;
                        memcpy(utxo.txid, txid, 32);
                        utxo.vout = j;
                        utxo.value = tx->outputs[j].value;
                        memcpy(utxo.pubkey_hash, tx->outputs[j].pubkey_hash, 20);
                        utxo.height = chain->best_height;
                        utxo.spent = false;
                        ftc_utxo_set_add(node->utxo_set, &utxo);
                    }
                }
                loaded++;
            }
        } else {
            /* Normal mode: full validation */
            if (ftc_chain_add_block(node, block)) {
                loaded++;
            } else {
                ftc_hash256_t hash;
                ftc_block_hash(block, hash);
                char hex[65];
                ftc_hash_to_hex(hash, hex);
                log_node("[NODE] Block %u rejected: %s\n", i, hex);
            }
        }

        ftc_block_free(block);
    }

    fclose(f);

    /* Remember how many blocks were in the file to prevent data loss */
    bool used_checkpoint = (loaded > 0 && count > 2014);  /* Used checkpoint loading */
    if ((node->config.recovery_mode || used_checkpoint) && loaded > 0) {
        /* In recovery/checkpoint mode, update loaded_block_count to actual loaded count
           to allow saving the blockchain */
        node->chain->loaded_block_count = loaded + 1;  /* +1 for genesis */
        if (node->config.recovery_mode) {
            log_node("[NODE] RECOVERY: Loaded %d blocks (was %u in file)\n", loaded, count);
        } else if (used_checkpoint) {
            log_node("[NODE] Loaded %d blocks using checkpoint\n", loaded);
        }
    } else {
        node->chain->loaded_block_count = count;
    }

    return loaded;
}

bool ftc_chain_init(ftc_chain_t* chain)
{
    /* Create genesis block using the mined genesis */
    ftc_block_t* genesis = ftc_genesis_block(true);  /* mainnet = true */
    if (!genesis) return false;

    chain->genesis = genesis;
    chain->best_height = 0;

    /* Add genesis to chain */
    if (chain->block_count >= chain->block_capacity && !expand_block_array(chain)) {
        chain_free(chain);
        return false;
    }

    /* Clone genesis for storage */
    ftc_block_t* genesis_copy = ftc_block_new();
    memcpy(&genesis_copy->header, &genesis->header, sizeof(ftc_block_header_t));
    for (uint32_t i = 0; i < genesis->tx_count; i++) {
        /* Deep copy transactions */
        size_t tx_size = ftc_tx_serialize(genesis->txs[i], NULL, 0);
        uint8_t* tx_data = (uint8_t*)malloc(tx_size);
        ftc_tx_serialize(genesis->txs[i], tx_data, tx_size);
        size_t consumed;
        ftc_tx_t* tx_copy = ftc_tx_deserialize(tx_data, tx_size, &consumed);
        free(tx_data);
        ftc_block_add_tx(genesis_copy, tx_copy);
    }

    chain->blocks[0] = genesis_copy;
    chain->block_count = 1;

    ftc_block_hash(genesis, chain->best_hash);

    /* Add genesis to hash index */
    hash_index_add(chain, chain->best_hash, 0);

    return true;
}

bool ftc_chain_add_block(ftc_node_t* node, ftc_block_t* block)
{
    ftc_chain_t* chain = node->chain;

    /* Compute block hash ONCE before any lock */
    ftc_hash256_t block_hash;
    ftc_block_hash(block, block_hash);

    /* Quick duplicate check with short lock */
    FTC_MUTEX_LOCK(chain->mutex);
    int existing = hash_index_find(chain, block_hash);
    if (existing >= 0) {
        /* Block already exists - reject silently */
        FTC_MUTEX_UNLOCK(chain->mutex);
        return false;
    }
    FTC_MUTEX_UNLOCK(chain->mutex);

    /* Clone block OUTSIDE the lock - this is slow */
    ftc_block_t* block_copy = clone_block(block);
    if (!block_copy) {
        return false;
    }

    /* Now acquire lock for the critical section */
    FTC_MUTEX_LOCK(chain->mutex);

    /* Double-check after re-acquiring lock (another thread might have added it) */
    existing = hash_index_find(chain, block_hash);
    if (existing >= 0) {
        FTC_MUTEX_UNLOCK(chain->mutex);
        ftc_block_free(block_copy);
        return false;
    }

    /* Validate block */
    if (!ftc_node_validate_block(node, block)) {
        FTC_MUTEX_UNLOCK(chain->mutex);
        ftc_block_free(block_copy);
        return false;
    }

    /* Expand if needed */
    if (chain->block_count >= chain->block_capacity && !expand_block_array(chain)) {
        log_node("[NODE] Failed to expand block storage\n");
        FTC_MUTEX_UNLOCK(chain->mutex);
        ftc_block_free(block_copy);
        return false;
    }

    chain->blocks[chain->block_count++] = block_copy;
    chain->best_height++;
    memcpy(chain->best_hash, block_hash, 32);

    /* Add to hash index for O(1) lookups */
    hash_index_add(chain, block_hash, chain->block_count - 1);

    /* Update UTXO set */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_tx_t* tx = block->txs[i];
        ftc_hash256_t txid;
        ftc_tx_hash(tx, txid);

        /* Remove spent UTXOs */
        if (!ftc_tx_is_coinbase(tx)) {
            for (uint32_t j = 0; j < tx->input_count; j++) {
                ftc_utxo_t* spent = ftc_utxo_set_remove(node->utxo_set, tx->inputs[j].prev_txid, tx->inputs[j].vout);
                if (spent) ftc_utxo_free(spent);
            }
        }

        /* Add new UTXOs */
        for (uint32_t j = 0; j < tx->output_count; j++) {
            ftc_utxo_t utxo;
            memcpy(utxo.txid, txid, 32);
            utxo.vout = j;
            utxo.value = tx->outputs[j].value;
            memcpy(utxo.pubkey_hash, tx->outputs[j].pubkey_hash, 20);
            utxo.height = chain->best_height;
            utxo.spent = false;
            ftc_utxo_set_add(node->utxo_set, &utxo);
        }
    }

    /* Update wallet if enabled */
    if (node->wallet) {
        ftc_wallet_process_block(node->wallet, block, chain->best_height);
    }

    /* Clear mempool of included transactions */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_hash256_t txid;
        ftc_tx_hash(block->txs[i], txid);
        ftc_mempool_remove(node->mempool, txid);
    }

    FTC_MUTEX_UNLOCK(chain->mutex);

    /* Save immediately for crash safety */
    char blocks_path[512];
    snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
    ftc_chain_save(chain, blocks_path);

    return true;
}

ftc_block_t* ftc_chain_get_block(ftc_chain_t* chain, const ftc_hash256_t hash)
{
    FTC_MUTEX_LOCK(chain->mutex);

    /* O(1) lookup using hash index */
    int index = hash_index_find(chain, hash);
    if (index >= 0 && index < chain->block_count) {
        ftc_block_t* block = chain->blocks[index];
        FTC_MUTEX_UNLOCK(chain->mutex);
        return block;
    }

    FTC_MUTEX_UNLOCK(chain->mutex);
    return NULL;
}

ftc_block_t* ftc_chain_get_block_at(ftc_chain_t* chain, uint32_t height)
{
    FTC_MUTEX_LOCK(chain->mutex);
    if (height < (uint32_t)chain->block_count) {
        ftc_block_t* block = chain->blocks[height];
        FTC_MUTEX_UNLOCK(chain->mutex);
        return block;
    }
    FTC_MUTEX_UNLOCK(chain->mutex);
    return NULL;
}

/*==============================================================================
 * VALIDATION
 *============================================================================*/

bool ftc_node_validate_block(ftc_node_t* node, const ftc_block_t* block)
{
    /* Check previous block */
    if (node->chain->block_count > 0) {
        ftc_hash256_t prev_hash;
        ftc_block_hash(node->chain->blocks[node->chain->block_count - 1], prev_hash);
        if (memcmp(block->header.prev_hash, prev_hash, 32) != 0) {
            return false;
        }
    }

    /* Check proof of work */
    ftc_hash256_t block_hash, target;
    ftc_block_hash(block, block_hash);
    ftc_bits_to_target(block->header.bits, target);

    bool valid_pow = true;
    for (int i = 31; i >= 0; i--) {
        if (block_hash[i] < target[i]) break;
        if (block_hash[i] > target[i]) {
            valid_pow = false;
            break;
        }
    }

    if (!valid_pow) {
        log_node("[NODE] Block fails PoW check\n");
        return false;
    }

    /* Check merkle root */
    ftc_hash256_t merkle;
    ftc_block_merkle_root(block, merkle);
    if (memcmp(merkle, block->header.merkle_root, 32) != 0) {
        log_node("[NODE] Block has wrong merkle root\n");
        return false;
    }

    /* Check timestamp */
    int64_t now = time(NULL);
    if (block->header.timestamp > now + 7200) {  /* 2 hours in future */
        log_node("[NODE] Block timestamp too far in future\n");
        return false;
    }

    /* Check transactions */
    if (block->tx_count == 0) {
        log_node("[NODE] Block has no transactions\n");
        return false;
    }

    /* First tx must be coinbase */
    if (!ftc_tx_is_coinbase(block->txs[0])) {
        log_node("[NODE] First tx is not coinbase\n");
        return false;
    }

    /* Check coinbase reward */
    uint32_t height = node->chain->best_height + 1;
    uint64_t reward = ftc_get_block_reward(height);
    uint64_t fees = 0;

    for (uint32_t i = 1; i < block->tx_count; i++) {
        /* Calculate fees */
        uint64_t in_value = 0;
        for (uint32_t j = 0; j < block->txs[i]->input_count; j++) {
            const ftc_utxo_t* utxo = ftc_utxo_set_get(node->utxo_set,
                block->txs[i]->inputs[j].prev_txid,
                block->txs[i]->inputs[j].prev_index);
            if (utxo) {
                in_value += utxo->value;
            }
        }
        uint64_t out_value = ftc_tx_output_value(block->txs[i]);
        if (in_value >= out_value) {
            fees += in_value - out_value;
        }
    }

    if (block->txs[0]->outputs[0].value > reward + fees) {
        log_node("[NODE] Coinbase reward too high\n");
        return false;
    }

    return true;
}

bool ftc_node_validate_tx(ftc_node_t* node, const ftc_tx_t* tx)
{
    /* Check not coinbase */
    if (ftc_tx_is_coinbase(tx)) {
        return false;
    }

    /* Check inputs exist and not spent */
    uint64_t in_value = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
        const ftc_utxo_t* utxo = ftc_utxo_set_get(node->utxo_set,
            tx->inputs[i].prev_txid, tx->inputs[i].prev_index);
        if (!utxo || utxo->spent) {
            return false;
        }
        in_value += utxo->value;
    }

    /* Check output value */
    uint64_t out_value = ftc_tx_output_value(tx);
    if (out_value > in_value) {
        return false;  /* Can't create money */
    }

    return true;
}

/*==============================================================================
 * MINING
 *============================================================================*/

ftc_block_t* ftc_node_create_block_template(ftc_node_t* node, const ftc_address_t miner_addr)
{
    ftc_block_t* block = ftc_block_new();
    if (!block) return NULL;

    /* Lock chain for reading */
    FTC_MUTEX_LOCK(node->chain->mutex);

    uint32_t height = node->chain->best_height + 1;

    /* Set header */
    block->header.version = 1;
    memcpy(block->header.prev_hash, node->chain->best_hash, 32);
    block->header.timestamp = (uint32_t)time(NULL);

    /* Calculate bits with difficulty adjustment */
    if (height == 0) {
        block->header.bits = FTC_GENESIS_BITS;
    } else if (height >= FTC_LWMA_ACTIVATION) {
        /* LWMA (Linearly Weighted Moving Average) - smooth per-block adjustment
         * This prevents difficulty oscillation when hashrate changes rapidly.
         * Recent blocks are weighted more heavily than older blocks.
         */
        int window = FTC_LWMA_WINDOW;
        if ((int)node->chain->block_count < window + 1) {
            window = node->chain->block_count - 1;
        }
        if (window < 1) window = 1;

        /* Calculate weighted sum of solve times */
        int64_t sum_weighted_time = 0;
        int64_t sum_weights = 0;

        for (int i = 1; i <= window; i++) {
            int idx = node->chain->block_count - window - 1 + i;
            if (idx < 1) idx = 1;
            int prev_idx = idx - 1;
            if (prev_idx < 0) prev_idx = 0;

            uint32_t block_time = node->chain->blocks[idx]->header.timestamp;
            uint32_t prev_time = node->chain->blocks[prev_idx]->header.timestamp;
            int32_t solve_time = (int32_t)(block_time - prev_time);

            /* Clamp solve time to reasonable bounds */
            if (solve_time < 1) solve_time = 1;
            if (solve_time > FTC_TARGET_BLOCK_TIME * 6) solve_time = FTC_TARGET_BLOCK_TIME * 6;

            /* Weight = position in window (1 to window) */
            int weight = i;
            sum_weighted_time += (int64_t)solve_time * weight;
            sum_weights += weight;
        }

        /* target_weighted_time = target_block_time * sum_weights */
        int64_t target_weighted_time = (int64_t)FTC_TARGET_BLOCK_TIME * sum_weights;

        /* Prevent division by zero */
        if (sum_weighted_time < 1) sum_weighted_time = 1;

        /* Get previous target */
        uint32_t prev_bits = node->chain->blocks[node->chain->block_count - 1]->header.bits;
        ftc_hash256_t target;
        ftc_bits_to_target(prev_bits, target);

        /* Calculate adjustment ratio with damping
         * new_target = prev_target * sum_weighted_time / target_weighted_time
         * Limit adjustment to 5% per block to prevent oscillation
         */
        int64_t ratio_num = sum_weighted_time;
        int64_t ratio_den = target_weighted_time;

        /* Limit adjustment to 5% per block for smooth difficulty changes
         * This prevents oscillation when hashrate changes rapidly
         * With 5% limit: 3x hashrate change takes ~22 blocks to stabilize
         */
        if (ratio_num > ratio_den * 21 / 20) ratio_num = ratio_den * 21 / 20;  /* Max 5% easier */
        if (ratio_num < ratio_den * 19 / 20) ratio_num = ratio_den * 19 / 20;  /* Max 5% harder */

        /* Apply adjustment to target */
        uint32_t t32[8];
        for (int i = 0; i < 8; i++) {
            t32[i] = (uint32_t)target[i*4] | ((uint32_t)target[i*4+1] << 8) |
                     ((uint32_t)target[i*4+2] << 16) | ((uint32_t)target[i*4+3] << 24);
        }

        /* Multiply by ratio_num */
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t prod = (uint64_t)t32[i] * ratio_num + carry;
            t32[i] = (uint32_t)prod;
            carry = prod >> 32;
        }

        /* Divide by ratio_den */
        uint64_t rem = 0;
        for (int i = 7; i >= 0; i--) {
            uint64_t div = (rem << 32) | t32[i];
            t32[i] = (uint32_t)(div / ratio_den);
            rem = div % ratio_den;
        }

        for (int i = 0; i < 8; i++) {
            target[i*4] = t32[i] & 0xff;
            target[i*4+1] = (t32[i] >> 8) & 0xff;
            target[i*4+2] = (t32[i] >> 16) & 0xff;
            target[i*4+3] = (t32[i] >> 24) & 0xff;
        }

        block->header.bits = ftc_target_to_bits(target);

        /* Log LWMA adjustment periodically */
        if (height % 100 == 0) {
            double diff = ftc_bits_to_difficulty(block->header.bits);
            log_node("[NODE] LWMA difficulty at height %u: %.2f (bits=0x%08x)\n",
                   height, diff, block->header.bits);
        }
    } else if (height % FTC_DIFFICULTY_INTERVAL != 0) {
        /* Legacy: Not at adjustment boundary - use previous bits */
        block->header.bits = node->chain->blocks[node->chain->block_count - 1]->header.bits;
    } else {
        /* Legacy: Difficulty adjustment at interval boundary (pre-LWMA) */
        int first_idx = node->chain->block_count - FTC_DIFFICULTY_INTERVAL;
        if (first_idx <= 0) first_idx = 1;

        uint32_t first_time = node->chain->blocks[first_idx]->header.timestamp;
        uint32_t last_time = node->chain->blocks[node->chain->block_count - 1]->header.timestamp;

        int32_t actual_time = (int32_t)(last_time - first_time);
        int blocks_counted = node->chain->block_count - 1 - first_idx;
        if (blocks_counted < 1) blocks_counted = 1;
        int32_t target_time = FTC_TARGET_BLOCK_TIME * blocks_counted;
        if (target_time < 1) target_time = 1;

        if (actual_time < target_time / 4) actual_time = target_time / 4;
        if (actual_time > target_time * 4) actual_time = target_time * 4;

        uint32_t prev_bits = node->chain->blocks[node->chain->block_count - 1]->header.bits;
        ftc_hash256_t target;
        ftc_bits_to_target(prev_bits, target);

        uint32_t t32[8];
        for (int i = 0; i < 8; i++) {
            t32[i] = (uint32_t)target[i*4] | ((uint32_t)target[i*4+1] << 8) |
                     ((uint32_t)target[i*4+2] << 16) | ((uint32_t)target[i*4+3] << 24);
        }

        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t prod = (uint64_t)t32[i] * actual_time + carry;
            t32[i] = (uint32_t)prod;
            carry = prod >> 32;
        }

        uint64_t rem = 0;
        for (int i = 7; i >= 0; i--) {
            uint64_t div = (rem << 32) | t32[i];
            t32[i] = (uint32_t)(div / target_time);
            rem = div % target_time;
        }

        for (int i = 0; i < 8; i++) {
            target[i*4] = t32[i] & 0xff;
            target[i*4+1] = (t32[i] >> 8) & 0xff;
            target[i*4+2] = (t32[i] >> 16) & 0xff;
            target[i*4+3] = (t32[i] >> 24) & 0xff;
        }

        block->header.bits = ftc_target_to_bits(target);
        log_node("[NODE] Legacy difficulty adjusted at height %u: bits=0x%08x\n", height, block->header.bits);
    }

    /* Emergency Difficulty Adjustment (EDA) - only for pre-LWMA heights */
    if (height < FTC_LWMA_ACTIVATION && node->chain->block_count > 0) {
        uint32_t last_block_time = node->chain->blocks[node->chain->block_count - 1]->header.timestamp;
        uint32_t current_time = (uint32_t)time(NULL);
        int32_t time_since_last = (int32_t)(current_time - last_block_time);

        const int32_t EDA_THRESHOLD = 600;  /* 10 minutes */
        if (time_since_last > EDA_THRESHOLD) {
            int eda_multiplier = time_since_last / EDA_THRESHOLD;
            if (eda_multiplier > 8) eda_multiplier = 8;

            ftc_hash256_t eda_target;
            ftc_bits_to_target(block->header.bits, eda_target);

            for (int shift = 0; shift < eda_multiplier; shift++) {
                uint8_t carry = 0;
                for (int i = 0; i < 32; i++) {
                    uint16_t val = ((uint16_t)eda_target[i] << 1) | carry;
                    eda_target[i] = val & 0xff;
                    carry = (val >> 8) & 1;
                }
            }

            block->header.bits = ftc_target_to_bits(eda_target);
            log_node("[NODE] EDA: %d min since last block, difficulty reduced %dx (bits=0x%08x)\n",
                   time_since_last / 60, 1 << eda_multiplier, block->header.bits);
        }
    }

    FTC_MUTEX_UNLOCK(node->chain->mutex);

    /* Add entropy to prevent template collision when multiple miners request same second */
    block->header.nonce = (uint32_t)rand() ^ ((uint32_t)clock() << 16);

    /* Create coinbase */
    uint64_t reward = ftc_get_block_reward(height);
    ftc_tx_t* coinbase = NULL;

    /* Check if P2Pool is active and has share contributors */
    if (node->p2pool && node->p2pool->pplns && node->p2pool->pplns->miner_count > 0) {
        /* P2Pool mode: distribute to all PPLNS contributors */
        coinbase = ftc_p2pool_create_coinbase(node->p2pool, height, reward, 0);
    }

    /* Fallback to single miner output if P2Pool not active or no shares */
    if (!coinbase) {
        coinbase = ftc_tx_create_coinbase(height, reward, NULL, 0);
        if (!coinbase) {
            ftc_block_free(block);
            FTC_MUTEX_UNLOCK(node->chain->mutex);
            return NULL;
        }
        /* Set coinbase output to miner address */
        memcpy(coinbase->outputs[0].pubkey_hash, miner_addr, 20);
    }

    ftc_block_add_tx(block, coinbase);

    /* Add mempool transactions */
    ftc_tx_t** mempool_txs = NULL;
    size_t mempool_count = 0;
    uint64_t total_fees = 0;
    ftc_mempool_select_transactions(node->mempool, FTC_MAX_BLOCK_SIZE - 1000, &mempool_txs, &mempool_count, &total_fees);

    for (size_t i = 0; i < mempool_count && block->tx_count < 1000; i++) {
        /* Clone transaction */
        size_t tx_size = ftc_tx_serialize(mempool_txs[i], NULL, 0);
        uint8_t* tx_data = (uint8_t*)malloc(tx_size);
        ftc_tx_serialize(mempool_txs[i], tx_data, tx_size);
        size_t consumed;
        ftc_tx_t* tx_copy = ftc_tx_deserialize(tx_data, tx_size, &consumed);
        free(tx_data);

        if (tx_copy) {
            ftc_block_add_tx(block, tx_copy);
        }
    }

    free(mempool_txs);

    /* Update merkle root */
    ftc_block_update_merkle(block);

    return block;
}

bool ftc_node_submit_block(ftc_node_t* node, ftc_block_t* block)
{
    if (!ftc_chain_add_block(node, block)) {
        return false;
    }

    return true;
}

/*==============================================================================
 * RPC HANDLERS
 *============================================================================*/

static ftc_block_t* rpc_get_block_by_hash(void* ctx, const ftc_hash256_t hash)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return ftc_chain_get_block(node->chain, hash);
}

static ftc_block_t* rpc_get_block_by_height(void* ctx, uint32_t height)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return ftc_chain_get_block_at(node->chain, height);
}

static uint32_t rpc_get_best_height(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return node->chain->best_height;
}

static void rpc_get_best_hash(void* ctx, ftc_hash256_t hash)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    memcpy(hash, node->chain->best_hash, 32);
}

static double rpc_get_difficulty(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    if (node->chain->block_count > 0) {
        return ftc_bits_to_difficulty(node->chain->blocks[node->chain->block_count - 1]->header.bits);
    }
    return 1.0;
}

static int rpc_get_peer_count(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    /* Return only P2P peer count (real node connections) */
    return node->p2p ? ftc_p2p_peer_count(node->p2p) : 0;
}

static int rpc_get_peer_info(void* ctx, char** addresses, int* ports, int64_t* ping_times, int max_peers)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    int count = 0;

    if (!node->p2p) return 0;

    /* Return connected P2P peers with their addresses and ping times */
    for (int i = 0; i < FTC_P2P_MAX_PEERS && count < max_peers; i++) {
        ftc_peer_t* peer = node->p2p->peers[i];
        if (!peer || peer->state != FTC_PEER_ESTABLISHED) continue;

        /* Convert IP to string */
        char ip_str[64] = {0};
        /* Check if it's IPv4-mapped IPv6 (::ffff:x.x.x.x) */
        if (peer->addr.ip[0] == 0 && peer->addr.ip[1] == 0 &&
            peer->addr.ip[10] == 0xFF && peer->addr.ip[11] == 0xFF) {
            /* IPv4 mapped address */
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     peer->addr.ip[12], peer->addr.ip[13],
                     peer->addr.ip[14], peer->addr.ip[15]);
        } else {
            /* Full IPv6 or simple IPv4 stored directly */
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     peer->addr.ip[12], peer->addr.ip[13],
                     peer->addr.ip[14], peer->addr.ip[15]);
        }

        snprintf(addresses[count], 64, "%s", ip_str);
        ports[count] = peer->addr.port;
        ping_times[count] = peer->ping_time;  /* RTT in ms */
        count++;
    }

    /* Also add known addresses from peer database */
    for (int i = 0; i < node->p2p->known_addr_count && count < max_peers; i++) {
        ftc_netaddr_t* addr = &node->p2p->known_addrs[i];

        /* Convert IP to string */
        char ip_str[64] = {0};
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                 addr->ip[12], addr->ip[13], addr->ip[14], addr->ip[15]);

        /* Skip if already in list (connected peer) */
        bool found = false;
        for (int j = 0; j < count; j++) {
            if (strcmp(addresses[j], ip_str) == 0 && ports[j] == addr->port) {
                found = true;
                break;
            }
        }
        if (found) continue;

        snprintf(addresses[count], 64, "%s", ip_str);
        ports[count] = addr->port;
        ping_times[count] = -1;  /* Unknown ping time for non-connected peers */
        count++;
    }

    return count;
}

static bool rpc_send_tx(void* ctx, ftc_tx_t* tx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;

    if (!ftc_node_validate_tx(node, tx)) {
        return false;
    }

    ftc_mempool_add(node->mempool, tx, node->utxo_set, node->chain->best_height);
    return true;
}

static ftc_mempool_t* rpc_get_mempool(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return node->mempool;
}

static bool rpc_get_balance(void* ctx, const ftc_address_t addr, uint64_t* balance)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    *balance = ftc_utxo_set_balance(node->utxo_set, addr, node->chain->best_height);
    return true;
}

static bool rpc_get_utxos(void* ctx, const ftc_address_t addr, ftc_utxo_t** utxos, size_t* count)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return ftc_utxo_set_get_by_address(node->utxo_set, addr, utxos, count);
}

static ftc_block_t* rpc_get_block_template(void* ctx, const ftc_address_t miner_addr)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return ftc_node_create_block_template(node, miner_addr);
}

static bool rpc_submit_block(void* ctx, ftc_block_t* block)
{
    ftc_node_t* node = (ftc_node_t*)ctx;

    /* Validate and add block */
    if (!ftc_chain_add_block(node, block)) {
        return false;
    }

    /* Broadcast to P2P network */
    if (node->p2p) {
        ftc_p2p_broadcast_block(node->p2p, block);
    }

    return true;
}

static const char* rpc_get_data_dir(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return node->config.data_dir;
}

/*==============================================================================
 * STRATUM RPC HANDLERS
 *============================================================================*/

static bool rpc_get_stratum_stats(void* ctx, int* miners, double* hashrate, uint64_t* shares, uint64_t* blocks)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    if (!node->stratum) {
        *miners = 0;
        *hashrate = 0;
        *shares = 0;
        *blocks = 0;
        return true;  /* Return empty stats instead of error */
    }

    ftc_stratum_stats_t stats;
    ftc_stratum_get_stats(node->stratum, &stats);

    *miners = stats.active_miners;
    *hashrate = stats.pool_hashrate;
    *shares = stats.total_shares;
    *blocks = stats.total_blocks;
    return true;
}

/*==============================================================================
 * P2POOL RPC HANDLERS
 *============================================================================*/

static bool rpc_p2pool_get_status(void* ctx, int* share_count, int* miner_count, uint64_t* total_work)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    if (!node->p2pool) return false;

    *share_count = (int)node->p2pool->total_shares;
    *miner_count = node->p2pool->pplns ? node->p2pool->pplns->miner_count : 0;
    *total_work = node->p2pool->pplns ? node->p2pool->pplns->total_work : 0;
    return true;
}

static bool rpc_p2pool_submit_share(void* ctx, const char* miner_addr, uint64_t work_done, const uint8_t* block_hash)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    if (!node->p2pool) return false;

    /* Create share from submission */
    ftc_share_t share = {0};
    share.version = 1;
    share.timestamp = (uint32_t)time(NULL);
    share.work_done = work_done;
    strncpy(share.miner_address, miner_addr, sizeof(share.miner_address) - 1);
    if (block_hash) {
        memcpy(share.block_hash, block_hash, 32);
    }

    /* Add share to P2Pool */
    ftc_p2pool_add_share(node->p2pool, &share);
    return true;
}

static int rpc_p2pool_get_payouts(void* ctx, uint64_t reward, char** addresses, uint64_t* amounts, int max_payouts)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    if (!node->p2pool) return 0;

    int count = 0;
    ftc_payout_t* payouts = ftc_p2pool_get_payouts(node->p2pool, reward, &count);
    if (!payouts) return 0;

    int result = count < max_payouts ? count : max_payouts;
    for (int i = 0; i < result; i++) {
        strncpy(addresses[i], payouts[i].address, 63);
        amounts[i] = payouts[i].amount;
    }

    free(payouts);
    return result;
}

/*==============================================================================
 * NODE LIFECYCLE
 *============================================================================*/

void ftc_node_config_default(ftc_node_config_t* config)
{
    memset(config, 0, sizeof(*config));
    config->rpc_port = FTC_RPC_PORT;
    config->p2p_port = FTC_MAINNET_PORT;
    config->stratum_port = STRATUM_DEFAULT_PORT;  /* 3333 */
    config->listen = true;  /* Accept incoming P2P connections by default */
    config->stratum_enabled = true;   /* Stratum enabled by default */
    strcpy(config->data_dir, FTC_DATA_DIR);
    config->wallet_enabled = true;
    config->log_level = 1;
}

ftc_node_t* ftc_node_new(const ftc_node_config_t* config)
{
    ftc_node_t* node = (ftc_node_t*)calloc(1, sizeof(ftc_node_t));
    if (!node) return NULL;

    memcpy(&node->config, config, sizeof(*config));

    /* Create chain */
    node->chain = chain_new();
    if (!node->chain) {
        free(node);
        return NULL;
    }

    /* Create mempool (default 300MB max) */
    node->mempool = ftc_mempool_new(300 * 1024 * 1024);
    if (!node->mempool) {
        chain_free(node->chain);
        free(node);
        return NULL;
    }

    /* Create UTXO set */
    node->utxo_set = ftc_utxo_set_new();
    if (!node->utxo_set) {
        ftc_mempool_free(node->mempool);
        chain_free(node->chain);
        free(node);
        return NULL;
    }

    /* Create RPC */
    node->rpc = ftc_rpc_new();

    /* Create wallet if enabled */
    if (config->wallet_enabled) {
        char wallet_path[512];
        snprintf(wallet_path, sizeof(wallet_path), "%s/wallet.dat", config->data_dir);

        node->wallet = ftc_wallet_load(wallet_path);
        if (!node->wallet) {
            node->wallet = ftc_wallet_new();
            if (node->wallet) {
                ftc_wallet_new_key(node->wallet, "default");
            }
        }
    }

    /* Create P2P network */
    uint16_t p2p_port = config->p2p_port ? config->p2p_port : FTC_MAINNET_PORT;
    node->p2p = ftc_p2p_new(node, p2p_port, config->listen);
    if (node->p2p) {
        /* Load saved peers */
        char peers_path[512];
        snprintf(peers_path, sizeof(peers_path), "%s/peers.dat", config->data_dir);
        ftc_p2p_load_peers(node->p2p, peers_path);
    }

    /* Create P2Pool for decentralized mining */
    node->p2pool = ftc_p2pool_new(node);

    /* Create Stratum server if enabled */
    if (config->stratum_enabled) {
        uint16_t stratum_port = config->stratum_port ? config->stratum_port : STRATUM_DEFAULT_PORT;
        node->stratum = ftc_stratum_new(node, stratum_port);
    }

    return node;
}

void ftc_node_free(ftc_node_t* node)
{
    if (!node) return;

    ftc_node_stop(node);

    /* Save blockchain to disk */
    if (node->chain && node->chain->block_count > 1) {
        char blocks_path[512];
        snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
        ftc_chain_save(node->chain, blocks_path);
    }

    if (node->wallet) {
        char wallet_path[512];
        snprintf(wallet_path, sizeof(wallet_path), "%s/wallet.dat", node->config.data_dir);
        ftc_wallet_save(node->wallet, wallet_path);
        ftc_wallet_free(node->wallet);
    }
    if (node->p2p) {
        /* Save peers before shutdown */
        char peers_path[512];
        snprintf(peers_path, sizeof(peers_path), "%s/peers.dat", node->config.data_dir);
        ftc_p2p_save_peers(node->p2p, peers_path);
        ftc_p2p_free(node->p2p);
    }
    if (node->p2pool) ftc_p2pool_free(node->p2pool);
    if (node->stratum) ftc_stratum_free(node->stratum);
    if (node->rpc) ftc_rpc_free(node->rpc);
    if (node->utxo_set) ftc_utxo_set_free(node->utxo_set);
    if (node->mempool) ftc_mempool_free(node->mempool);
    if (node->chain) chain_free(node->chain);

    free(node);
}

bool ftc_node_start(ftc_node_t* node)
{
    node->start_time = time(NULL);

    /* Initialize chain */
    if (!ftc_chain_init(node->chain)) {
        log_node("[NODE] Failed to initialize chain\n");
        return false;
    }

    /* Load blockchain from disk */
    char blocks_path[512];
    snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
    ftc_chain_load(node, blocks_path);

    /* In recovery/checkpoint mode, force save if we loaded more than 2014 blocks */
    bool should_save = node->config.recovery_mode ||
                       (node->chain->block_count > 2015);  /* Used checkpoint loading */
    if (should_save && node->chain->block_count > 1) {
        log_node("[NODE] Saving blockchain (%d blocks)...\n", node->chain->block_count);
        if (ftc_chain_save(node->chain, blocks_path)) {
            log_node("[NODE] Blockchain saved successfully!\n");
        } else {
            log_node("[NODE] WARNING - Failed to save blockchain!\n");
        }
    }

    /* Initialize auto-save state */
    node->last_save_height = node->chain->best_height;
    node->last_save_time = time(NULL);

    /* Setup RPC handlers */
    static ftc_rpc_handlers_t rpc_handlers = {
        .get_block_by_hash = rpc_get_block_by_hash,
        .get_block_by_height = rpc_get_block_by_height,
        .get_best_height = rpc_get_best_height,
        .get_best_hash = rpc_get_best_hash,
        .get_difficulty = rpc_get_difficulty,
        .get_peer_count = rpc_get_peer_count,
        .get_peer_info = rpc_get_peer_info,
        .send_tx = rpc_send_tx,
        .get_mempool = rpc_get_mempool,
        .get_balance = rpc_get_balance,
        .get_utxos = rpc_get_utxos,
        .get_block_template = rpc_get_block_template,
        .submit_block = rpc_submit_block,
        .get_data_dir = rpc_get_data_dir,
        .p2pool_get_status = rpc_p2pool_get_status,
        .p2pool_submit_share = rpc_p2pool_submit_share,
        .p2pool_get_payouts = rpc_p2pool_get_payouts,
        .get_stratum_stats = rpc_get_stratum_stats,
    };
    rpc_handlers.user_data = node;
    ftc_rpc_set_handlers(node->rpc, &rpc_handlers);

    /* Start RPC */
    ftc_rpc_start(node->rpc, node->config.rpc_port);

    /* Start P2P network */
    if (node->p2p) {
        if (ftc_p2p_start(node->p2p)) {
            /* Connect to manually specified nodes (-addnode / -peers) */
            for (int i = 0; i < node->config.connect_node_count; i++) {
                const char* addr = node->config.connect_nodes[i];
                if (!addr) continue;

                /* Parse host:port */
                char host[256];
                uint16_t port = FTC_MAINNET_PORT;
                strncpy(host, addr, sizeof(host) - 1);
                char* colon = strchr(host, ':');
                if (colon) {
                    *colon = '\0';
                    port = (uint16_t)atoi(colon + 1);
                }

                ftc_p2p_connect(node->p2p, host, port);
            }
        }
    }

    /* Start Stratum server if enabled */
    if (node->stratum) {
        ftc_stratum_start(node->stratum);
    }

    node->running = true;
    return true;
}

void ftc_node_stop(ftc_node_t* node)
{
    if (!node->running) return;

    /* Stop Stratum server */
    if (node->stratum) {
        ftc_stratum_stop(node->stratum);
    }

    /* Stop P2P */
    if (node->p2p) {
        ftc_p2p_stop(node->p2p);
    }

    ftc_rpc_stop(node->rpc);

    node->running = false;
}

void ftc_node_poll(ftc_node_t* node)
{
    /* Process P2P network */
    if (node->p2p) {
        ftc_p2p_poll(node->p2p);
    }

    /* Process Stratum server */
    if (node->stratum) {
        ftc_stratum_poll(node->stratum);
    }

    /* Process RPC */
    ftc_rpc_poll(node->rpc, 10);

    /* Auto-save blockchain every 60 seconds if new blocks arrived */
    uint32_t height = node->chain->best_height;
    int64_t now = time(NULL);
    if (height > node->last_save_height && (now - node->last_save_time) >= 60) {
        char blocks_path[512];
        snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
        if (ftc_chain_save(node->chain, blocks_path)) {
            node->last_save_height = height;
            node->last_save_time = now;
        }
    }
}

/*==============================================================================
 * NODE RUN LOOP (Background daemon mode)
 *============================================================================*/

void ftc_node_run(ftc_node_t* node)
{
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    printf("FTC Node v%s running. Press Ctrl+C to stop.\n", FTC_NODE_VERSION);
    fflush(stdout);

    node->prev_height = node->chain->best_height;

    /* Silent background loop */
    while (node->running && !g_shutdown_requested) {
        ftc_node_poll(node);

        /* Track new blocks */
        if (node->chain->best_height > node->prev_height) {
            uint32_t new_blocks = node->chain->best_height - node->prev_height;
            node->blocks_received += new_blocks;
            node->last_block_time = time(NULL);
            node->prev_height = node->chain->best_height;
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    ftc_node_stop(node);
}
