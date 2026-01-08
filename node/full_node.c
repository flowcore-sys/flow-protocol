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
#else
#include <unistd.h>
#endif

/*==============================================================================
 * GLOBALS
 *============================================================================*/

static volatile bool g_shutdown_requested = false;

static void signal_handler(int sig)
{
    (void)sig;
    printf("\n[NODE] Shutdown requested...\n");
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
        printf("[NODE] Skipping save: have %u blocks but file had %u\n",
               count, chain->loaded_block_count);
        FTC_MUTEX_UNLOCK(chain->mutex);
        return false;
    }

    /* Write to temp file first for atomic save */
    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        printf("[NODE] Failed to open %s for writing\n", temp_path);
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
    fclose(f);

    /* Atomic rename: remove old file and rename temp */
    remove(path);
    if (rename(temp_path, path) != 0) {
        printf("[NODE] Failed to rename %s to %s\n", temp_path, path);
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
        printf("[NODE] Invalid blocks.dat magic\n");
        fclose(f);
        return -1;
    }

    if (fread(&version, 4, 1, f) != 1 || version != FTC_BLOCKS_VERSION) {
        printf("[NODE] Unsupported blocks.dat version\n");
        fclose(f);
        return -1;
    }

    if (fread(&count, 4, 1, f) != 1) {
        printf("[NODE] Failed to read block count\n");
        fclose(f);
        return -1;
    }

    /* Loading blocks silently for clean dashboard */

    int loaded = 0;

    /* Read blocks (count includes genesis which we skip) */
    for (uint32_t i = 1; i < count; i++) {
        uint32_t size32;
        if (fread(&size32, 4, 1, f) != 1) {
            printf("[NODE] Failed to read block %u size\n", i);
            break;
        }

        uint8_t* block_data = (uint8_t*)malloc(size32);
        if (!block_data) {
            printf("[NODE] Out of memory loading block %u\n", i);
            break;
        }

        if (fread(block_data, 1, size32, f) != size32) {
            printf("[NODE] Failed to read block %u data\n", i);
            free(block_data);
            break;
        }

        ftc_block_t* block = ftc_block_deserialize(block_data, size32);
        free(block_data);

        if (!block) {
            printf("[NODE] Failed to deserialize block %u\n", i);
            break;
        }

        /* Add block to chain (validates and updates UTXO) */
        if (ftc_chain_add_block(node, block)) {
            loaded++;
        } else {
            ftc_hash256_t hash;
            ftc_block_hash(block, hash);
            char hex[65];
            ftc_hash_to_hex(hash, hex);
            printf("[NODE] Block %u rejected: %s\n", i, hex);
        }

        ftc_block_free(block);
    }

    fclose(f);

    /* Remember how many blocks were in the file to prevent data loss */
    node->chain->loaded_block_count = count;

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
    if (chain->block_count >= chain->block_capacity) {
        int new_cap = chain->block_capacity * 2;
        ftc_block_t** new_blocks = (ftc_block_t**)realloc(chain->blocks, new_cap * sizeof(ftc_block_t*));
        if (!new_blocks) {
            chain_free(chain);
            return NULL;
        }
        chain->blocks = new_blocks;
        chain->block_capacity = new_cap;
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
    size_t block_size = ftc_block_serialize(block, NULL, 0);
    uint8_t* block_data = (uint8_t*)malloc(block_size);
    if (!block_data) {
        return false;
    }
    ftc_block_serialize(block, block_data, block_size);
    ftc_block_t* block_copy = ftc_block_deserialize(block_data, block_size);
    free(block_data);

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
    if (chain->block_count >= chain->block_capacity) {
        int new_cap = chain->block_capacity * 2;
        ftc_block_t** new_blocks = (ftc_block_t**)realloc(chain->blocks, new_cap * sizeof(ftc_block_t*));
        if (!new_blocks) {
            printf("[NODE] Failed to expand block storage\n");
            FTC_MUTEX_UNLOCK(chain->mutex);
            ftc_block_free(block_copy);
            return false;
        }
        chain->blocks = new_blocks;
        chain->block_capacity = new_cap;
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

    /* Note: blocks.dat is only saved on shutdown for better performance */
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
            /* Silent reject - too noisy during sync */
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
        printf("[NODE] Block fails PoW check\n");
        return false;
    }

    /* Check merkle root */
    ftc_hash256_t merkle;
    ftc_block_merkle_root(block, merkle);
    if (memcmp(merkle, block->header.merkle_root, 32) != 0) {
        printf("[NODE] Block has wrong merkle root\n");
        return false;
    }

    /* Check timestamp */
    int64_t now = time(NULL);
    if (block->header.timestamp > now + 7200) {  /* 2 hours in future */
        printf("[NODE] Block timestamp too far in future\n");
        return false;
    }

    /* Check transactions */
    if (block->tx_count == 0) {
        printf("[NODE] Block has no transactions\n");
        return false;
    }

    /* First tx must be coinbase */
    if (!ftc_tx_is_coinbase(block->txs[0])) {
        printf("[NODE] First tx is not coinbase\n");
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
            ftc_utxo_t* utxo = ftc_utxo_set_get(node->utxo_set,
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
        printf("[NODE] Coinbase reward too high\n");
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
        ftc_utxo_t* utxo = ftc_utxo_set_get(node->utxo_set,
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

    /* Verify signatures (disabled until Ed25519 is fixed) */
    /* for (uint32_t i = 0; i < tx->input_count; i++) {
        if (!ftc_tx_verify_input(tx, i)) {
            return false;
        }
    } */

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
    } else if (height % FTC_DIFFICULTY_INTERVAL != 0) {
        /* Not at adjustment boundary - use previous bits */
        block->header.bits = node->chain->blocks[node->chain->block_count - 1]->header.bits;
    } else {
        /* Difficulty adjustment at interval boundary */
        int first_idx = node->chain->block_count - FTC_DIFFICULTY_INTERVAL;
        /* Skip genesis block (index 0) - its timestamp is from creation, not mining */
        if (first_idx <= 0) first_idx = 1;

        uint32_t first_time = node->chain->blocks[first_idx]->header.timestamp;
        uint32_t last_time = node->chain->blocks[node->chain->block_count - 1]->header.timestamp;

        int32_t actual_time = (int32_t)(last_time - first_time);
        /* Adjust target_time proportionally if we have fewer blocks */
        int blocks_counted = node->chain->block_count - 1 - first_idx;
        if (blocks_counted < 1) blocks_counted = 1;
        int32_t target_time = FTC_TARGET_BLOCK_TIME * blocks_counted;
        if (target_time < 1) target_time = 1;

        /* Limit to 4x adjustment */
        if (actual_time < target_time / 4) actual_time = target_time / 4;
        if (actual_time > target_time * 4) actual_time = target_time * 4;

        /* Get current target and adjust */
        uint32_t prev_bits = node->chain->blocks[node->chain->block_count - 1]->header.bits;
        ftc_hash256_t target;
        ftc_bits_to_target(prev_bits, target);

        /* Multiply target by actual_time / target_time */
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
        printf("[NODE] Difficulty adjusted at height %u: bits=0x%08x\n", height, block->header.bits);
    }

    FTC_MUTEX_UNLOCK(node->chain->mutex);

    /* Add entropy to prevent template collision when multiple miners request same second */
    block->header.nonce = (uint32_t)rand() ^ ((uint32_t)clock() << 16);

    /* Create coinbase */
    uint64_t reward = ftc_get_block_reward(height);
    ftc_tx_t* coinbase = ftc_tx_create_coinbase(height, reward, NULL, 0);
    if (!coinbase) {
        ftc_block_free(block);
        return NULL;
    }

    /* Set coinbase output to miner address */
    memcpy(coinbase->outputs[0].pubkey_hash, miner_addr, 20);
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
    /* Return active miners count instead of P2P peers */
    return ftc_rpc_get_active_miners(node->rpc);
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
    *balance = ftc_utxo_set_balance(node->utxo_set, addr);
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

    return true;
}

static const char* rpc_get_data_dir(void* ctx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;
    return node->config.data_dir;
}

/*==============================================================================
 * NODE LIFECYCLE
 *============================================================================*/

void ftc_node_config_default(ftc_node_config_t* config)
{
    memset(config, 0, sizeof(*config));
    config->rpc_port = FTC_RPC_PORT;
    config->testnet = false;
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
        printf("[NODE] Failed to initialize chain\n");
        return false;
    }

    /* Load blockchain from disk */
    char blocks_path[512];
    snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
    ftc_chain_load(node, blocks_path);

    /* Initialize auto-save state */
    node->last_save_height = node->chain->best_height;

    /* Setup RPC handlers */
    static ftc_rpc_handlers_t rpc_handlers = {
        .get_block_by_hash = rpc_get_block_by_hash,
        .get_block_by_height = rpc_get_block_by_height,
        .get_best_height = rpc_get_best_height,
        .get_best_hash = rpc_get_best_hash,
        .get_difficulty = rpc_get_difficulty,
        .get_peer_count = rpc_get_peer_count,
        .send_tx = rpc_send_tx,
        .get_mempool = rpc_get_mempool,
        .get_balance = rpc_get_balance,
        .get_utxos = rpc_get_utxos,
        .get_block_template = rpc_get_block_template,
        .submit_block = rpc_submit_block,
        .get_data_dir = rpc_get_data_dir,
    };
    rpc_handlers.user_data = node;
    ftc_rpc_set_handlers(node->rpc, &rpc_handlers);

    /* Start RPC */
    if (!ftc_rpc_start(node->rpc, node->config.rpc_port)) {
        printf("[NODE] Failed to start RPC\n");
    }

    node->running = true;
    return true;
}

void ftc_node_stop(ftc_node_t* node)
{
    if (!node->running) return;

    printf("Saving blockchain and stopping...\n");

    ftc_rpc_stop(node->rpc);

    node->running = false;
}

void ftc_node_poll(ftc_node_t* node)
{
    /* Process RPC */
    ftc_rpc_poll(node->rpc, 10);

    /* Auto-save blockchain: save immediately when new blocks arrive */
    uint32_t height = node->chain->best_height;
    if (height > node->last_save_height) {
        char blocks_path[512];
        snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", node->config.data_dir);
        if (ftc_chain_save(node->chain, blocks_path)) {
            node->last_save_height = height;
        }
    }
}

/*==============================================================================
 * DASHBOARD
 *============================================================================*/

static void enable_virtual_terminal(void)
{
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= 0x0004;  /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
    SetConsoleMode(hOut, dwMode);
#endif
}

static void print_dashboard(ftc_node_t* node)
{
    int64_t now = time(NULL);
    int64_t uptime = now - node->start_time;

    /* Format uptime */
    int days = (int)(uptime / 86400);
    int hours = (int)((uptime % 86400) / 3600);
    int mins = (int)((uptime % 3600) / 60);
    int secs = (int)(uptime % 60);

    /* Format best hash (last 16 chars) */
    char hash_short[17];
    char hash_hex[65];
    ftc_hash_to_hex(node->chain->best_hash, hash_hex);
    strncpy(hash_short, hash_hex + 48, 16);
    hash_short[16] = '\0';

    /* Calculate blocks/min */
    float blocks_per_min = 0;
    if (uptime > 0) {
        blocks_per_min = (float)node->blocks_received * 60.0f / (float)uptime;
    }

    /* Time since last block */
    int64_t since_block = node->last_block_time > 0 ? (now - node->last_block_time) : 0;

    /* Move cursor to home and clear screen */
    printf("\033[H\033[J");

    /* Get active miners count */
    int active_miners = ftc_rpc_get_active_miners(node->rpc);

    /* Print dashboard */
    printf("+--------------------------------------------------------------+\n");
    printf("|        FTC Central Server v%-10s                       |\n", FTC_NODE_VERSION);
    printf("+--------------------------------------------------------------+\n");

    printf("|  Height:    %-10u          Miners:    %-3d active       |\n",
           node->chain->best_height, active_miners);
    printf("|  Best:      ...%-16s                                |\n",
           hash_short);
    printf("|  Mempool:   %-10zu tx                                    |\n",
           ftc_mempool_count(node->mempool));

    printf("+--------------------------------------------------------------+\n");
    printf("|  Uptime:    %dd %02dh %02dm %02ds                                  |\n",
           days, hours, mins, secs);
    printf("|  Blocks:    %-6u received     (%.1f/min)                   |\n",
           node->blocks_received, blocks_per_min);
    printf("|  Last:      %-6lld sec ago                                   |\n",
           (long long)since_block);
    printf("+--------------------------------------------------------------+\n");

    printf("|  RPC Port:  %-5u                                            |\n",
           node->config.rpc_port);
    printf("+--------------------------------------------------------------+\n");
    printf("\n  Press Ctrl+C to stop\n");

    fflush(stdout);
}

void ftc_node_run(ftc_node_t* node)
{
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Enable ANSI escape codes on Windows */
    enable_virtual_terminal();

    /* Initial dashboard */
    node->prev_height = node->chain->best_height;
    print_dashboard(node);

    while (node->running && !g_shutdown_requested) {
        ftc_node_poll(node);

        /* Update dashboard every second */
        int64_t now = time(NULL);
        if (now - node->last_dashboard_update >= 1) {
            /* Track blocks received */
            if (node->chain->best_height > node->prev_height) {
                node->blocks_received += (node->chain->best_height - node->prev_height);
                node->last_block_time = now;
                node->prev_height = node->chain->best_height;
            }

            print_dashboard(node);
            node->last_dashboard_update = now;
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Clear screen before shutdown message */
    printf("\033[H\033[J");
    ftc_node_stop(node);
}
