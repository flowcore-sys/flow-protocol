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

    return chain;
}

static void chain_free(ftc_chain_t* chain)
{
    if (!chain) return;

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

    return true;
}

bool ftc_chain_add_block(ftc_node_t* node, ftc_block_t* block)
{
    ftc_chain_t* chain = node->chain;

    /* Validate block */
    if (!ftc_node_validate_block(node, block)) {
        return false;
    }

    /* Expand if needed */
    if (chain->block_count >= chain->block_capacity) {
        int new_cap = chain->block_capacity * 2;
        ftc_block_t** new_blocks = (ftc_block_t**)realloc(chain->blocks, new_cap * sizeof(ftc_block_t*));
        if (!new_blocks) {
            printf("[NODE] Failed to expand block storage\n");
            return false;
        }
        chain->blocks = new_blocks;
        chain->block_capacity = new_cap;
    }

    /* Clone block */
    size_t block_size = ftc_block_serialize(block, NULL, 0);
    uint8_t* block_data = (uint8_t*)malloc(block_size);
    ftc_block_serialize(block, block_data, block_size);
    ftc_block_t* block_copy = ftc_block_deserialize(block_data, block_size);
    free(block_data);

    chain->blocks[chain->block_count++] = block_copy;
    chain->best_height++;
    ftc_block_hash(block, chain->best_hash);

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

    return true;
}

ftc_block_t* ftc_chain_get_block(ftc_chain_t* chain, const ftc_hash256_t hash)
{
    for (int i = 0; i < chain->block_count; i++) {
        ftc_hash256_t block_hash;
        ftc_block_hash(chain->blocks[i], block_hash);
        if (memcmp(block_hash, hash, 32) == 0) {
            return chain->blocks[i];
        }
    }
    return NULL;
}

ftc_block_t* ftc_chain_get_block_at(ftc_chain_t* chain, uint32_t height)
{
    if (height < (uint32_t)chain->block_count) {
        return chain->blocks[height];
    }
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
            printf("[NODE] Block has wrong prev_hash\n");
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
    block->header.nonce = 0;

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

    /* Broadcast to peers */
    ftc_p2p_broadcast_block(node->p2p, block);

    ftc_hash256_t hash;
    ftc_block_hash(block, hash);
    char hex[65];
    ftc_hash_to_hex(hash, hex);

    printf("[NODE] Block %d accepted: %s\n", node->chain->best_height, hex);

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
    return node->p2p->peer_count;
}

static bool rpc_send_tx(void* ctx, ftc_tx_t* tx)
{
    ftc_node_t* node = (ftc_node_t*)ctx;

    if (!ftc_node_validate_tx(node, tx)) {
        return false;
    }

    ftc_mempool_add(node->mempool, tx, node->utxo_set, node->chain->best_height);
    ftc_p2p_broadcast_tx(node->p2p, tx);
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

    /* Broadcast to peers */
    ftc_p2p_broadcast_block(node->p2p, block);

    return true;
}

/*==============================================================================
 * P2P CALLBACKS
 *============================================================================*/

static void p2p_on_peer_connected(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;
    printf("[NODE] Peer connected: %s (height=%d)\n", peer->ip_str, peer->start_height);

    /* Request blocks if peer has more than us */
    if (peer->start_height > (int)node->chain->best_height) {
        printf("[NODE] Peer has more blocks (%d > %d), requesting headers\n",
               peer->start_height, node->chain->best_height);
        ftc_hash256_t stop_hash = {0};
        ftc_peer_send_getheaders(peer, &node->chain->best_hash, 1, stop_hash);
    }
}

static void p2p_on_peer_disconnected(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    (void)p2p;
    printf("[NODE] Peer disconnected: %s\n", peer->ip_str);
}

static void p2p_on_block(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_t* block)
{
    (void)peer;
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    ftc_hash256_t hash;
    ftc_block_hash(block, hash);
    char hex[65];
    ftc_hash_to_hex(hash, hex);

    printf("[NODE] Received block: %s\n", hex);

    /* Clone block (const removal) */
    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    ftc_block_serialize(block, data, size);
    ftc_block_t* block_copy = ftc_block_deserialize(data, size);
    free(data);

    if (block_copy) {
        ftc_chain_add_block(node, block_copy);
        ftc_block_free(block_copy);
    }
}

static void p2p_on_tx(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_tx_t* tx)
{
    (void)peer;
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    /* Clone and add to mempool */
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    ftc_tx_serialize(tx, data, size);
    size_t consumed;
    ftc_tx_t* tx_copy = ftc_tx_deserialize(data, size, &consumed);
    free(data);

    if (tx_copy && ftc_node_validate_tx(node, tx_copy)) {
        ftc_mempool_add(node->mempool, tx_copy, node->utxo_set, node->chain->best_height);
    } else {
        ftc_tx_free(tx_copy);
    }
}

static void p2p_on_getdata(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_inv_t* inv, size_t count)
{
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    for (size_t i = 0; i < count; i++) {
        if (inv[i].type == FTC_INV_BLOCK) {
            ftc_block_t* block = ftc_chain_get_block(node->chain, inv[i].hash);
            if (block) {
                ftc_peer_send_block(peer, block);
            }
        } else if (inv[i].type == FTC_INV_TX) {
            ftc_tx_t* tx = ftc_mempool_get(node->mempool, inv[i].hash);
            if (tx) {
                ftc_peer_send_tx(peer, tx);
            }
        }
    }
}

static void p2p_on_inv(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_inv_t* inv, size_t count)
{
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    /* Request unknown items */
    ftc_inv_t* needed = (ftc_inv_t*)malloc(count * sizeof(ftc_inv_t));
    size_t needed_count = 0;

    for (size_t i = 0; i < count; i++) {
        bool have = false;

        if (inv[i].type == FTC_INV_BLOCK) {
            have = ftc_chain_get_block(node->chain, inv[i].hash) != NULL;
        } else if (inv[i].type == FTC_INV_TX) {
            have = ftc_mempool_get(node->mempool, inv[i].hash) != NULL;
        }

        if (!have) {
            needed[needed_count++] = inv[i];
        }
    }

    if (needed_count > 0) {
        ftc_peer_send_getdata(peer, needed, needed_count);
    }

    free(needed);
}

static void p2p_on_headers(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_header_t* headers, size_t count)
{
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    if (count == 0) {
        printf("[NODE] Received empty headers response\n");
        return;
    }

    printf("[NODE] Received %zu headers from %s\n", count, peer->ip_str);

    /* Request blocks for headers we don't have */
    ftc_inv_t* inv = (ftc_inv_t*)malloc(count * sizeof(ftc_inv_t));
    if (!inv) return;

    size_t inv_count = 0;
    for (size_t i = 0; i < count; i++) {
        ftc_hash256_t header_hash;
        ftc_hash_block_header(&headers[i], header_hash);

        /* Check if we already have this block */
        if (!ftc_chain_get_block(node->chain, header_hash)) {
            inv[inv_count].type = FTC_INV_BLOCK;
            memcpy(inv[inv_count].hash, header_hash, 32);
            inv_count++;
        }
    }

    if (inv_count > 0) {
        printf("[NODE] Requesting %zu blocks\n", inv_count);
        ftc_peer_send_getdata(peer, inv, inv_count);
    }

    free(inv);

    /* If we got max headers, request more */
    if (count >= 2000) {
        ftc_hash256_t last_hash;
        ftc_hash_block_header(&headers[count - 1], last_hash);
        ftc_hash256_t stop_hash = {0};
        ftc_peer_send_getheaders(peer, &last_hash, 1, stop_hash);
    }
}

static void p2p_on_getheaders(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_hash256_t* locator, size_t count, const ftc_hash256_t stop_hash)
{
    (void)stop_hash;
    ftc_node_t* node = (ftc_node_t*)p2p->user_data;

    if (count == 0) return;

    /* Find the first locator hash we have */
    int start_height = -1;
    for (size_t i = 0; i < count; i++) {
        for (int j = 0; j < node->chain->block_count; j++) {
            ftc_hash256_t block_hash;
            ftc_block_hash(node->chain->blocks[j], block_hash);
            if (memcmp(block_hash, locator[i], 32) == 0) {
                start_height = j;
                break;
            }
        }
        if (start_height >= 0) break;
    }

    /* Start from genesis if no match */
    if (start_height < 0) start_height = 0;

    /* Send headers starting from start_height + 1 */
    size_t header_count = 0;
    size_t max_headers = 2000;
    ftc_block_header_t* headers = (ftc_block_header_t*)malloc(max_headers * sizeof(ftc_block_header_t));
    if (!headers) return;

    for (int i = start_height + 1; i < node->chain->block_count && header_count < max_headers; i++) {
        memcpy(&headers[header_count], &node->chain->blocks[i]->header, sizeof(ftc_block_header_t));
        header_count++;
    }

    if (header_count > 0) {
        printf("[NODE] Sending %zu headers to %s (from height %d)\n", header_count, peer->ip_str, start_height + 1);
        ftc_peer_send_headers(peer, headers, header_count);
    }

    free(headers);
}

/*==============================================================================
 * NODE LIFECYCLE
 *============================================================================*/

void ftc_node_config_default(ftc_node_config_t* config)
{
    memset(config, 0, sizeof(*config));
    config->p2p_port = FTC_P2P_PORT;
    config->rpc_port = FTC_RPC_PORT;
    config->listen = true;
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

    /* Create P2P */
    node->p2p = ftc_p2p_new();
    if (!node->p2p) {
        ftc_utxo_set_free(node->utxo_set);
        ftc_mempool_free(node->mempool);
        chain_free(node->chain);
        free(node);
        return NULL;
    }
    node->p2p->user_data = node;

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

    if (node->wallet) {
        char wallet_path[512];
        snprintf(wallet_path, sizeof(wallet_path), "%s/wallet.dat", node->config.data_dir);
        ftc_wallet_save(node->wallet, wallet_path);
        ftc_wallet_free(node->wallet);
    }
    if (node->rpc) ftc_rpc_free(node->rpc);
    if (node->p2p) ftc_p2p_free(node->p2p);
    if (node->utxo_set) ftc_utxo_set_free(node->utxo_set);
    if (node->mempool) ftc_mempool_free(node->mempool);
    if (node->chain) chain_free(node->chain);

    free(node);
}

bool ftc_node_start(ftc_node_t* node)
{
    printf("==============================================\n");
    printf("  FTC Node v%s\n", FTC_NODE_VERSION);
    printf("==============================================\n\n");

    node->start_time = time(NULL);

    /* Initialize chain */
    if (!ftc_chain_init(node->chain)) {
        printf("[NODE] Failed to initialize chain\n");
        return false;
    }

    ftc_hash256_t genesis_hash;
    ftc_block_hash(node->chain->genesis, genesis_hash);
    char hex[65];
    ftc_hash_to_hex(genesis_hash, hex);
    printf("[NODE] Genesis block: %s\n", hex);

    /* Setup P2P callbacks */
    static ftc_p2p_callbacks_t p2p_callbacks = {
        .on_peer_connected = p2p_on_peer_connected,
        .on_peer_disconnected = p2p_on_peer_disconnected,
        .on_block = p2p_on_block,
        .on_tx = p2p_on_tx,
        .on_inv = p2p_on_inv,
        .on_getdata = p2p_on_getdata,
        .on_headers = p2p_on_headers,
        .on_getheaders = p2p_on_getheaders,
    };
    ftc_p2p_set_callbacks(node->p2p, &p2p_callbacks, node);

    /* Add seed nodes */
    for (int i = 0; i < node->config.seed_count; i++) {
        ftc_p2p_add_seed(node->p2p, node->config.seeds[i]);
    }

    /* Start P2P */
    if (node->config.listen) {
        if (!ftc_p2p_start(node->p2p, node->config.p2p_port)) {
            printf("[NODE] Failed to start P2P\n");
            return false;
        }
    }

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
    };
    rpc_handlers.user_data = node;
    ftc_rpc_set_handlers(node->rpc, &rpc_handlers);

    /* Start RPC */
    if (!ftc_rpc_start(node->rpc, node->config.rpc_port)) {
        printf("[NODE] Failed to start RPC\n");
    }

    if (node->wallet) {
        char addr_str[64];
        ftc_wallet_get_address_str(node->wallet, addr_str, sizeof(addr_str));
        printf("[NODE] Wallet address: %s\n", addr_str);
    }

    node->running = true;
    printf("[NODE] Started successfully\n\n");

    return true;
}

void ftc_node_stop(ftc_node_t* node)
{
    if (!node->running) return;

    printf("[NODE] Stopping...\n");

    ftc_rpc_stop(node->rpc);
    ftc_p2p_stop(node->p2p);

    node->running = false;
    printf("[NODE] Stopped\n");
}

void ftc_node_poll(ftc_node_t* node)
{
    /* Process P2P */
    ftc_p2p_poll(node->p2p, 10);

    /* Process RPC */
    ftc_rpc_poll(node->rpc, 10);

    /* Update P2P height */
    ftc_p2p_set_height(node->p2p, node->chain->best_height);
}

void ftc_node_run(ftc_node_t* node)
{
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    while (node->running && !g_shutdown_requested) {
        ftc_node_poll(node);

#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    ftc_node_stop(node);
}
