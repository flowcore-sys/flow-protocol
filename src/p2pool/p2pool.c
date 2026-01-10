/**
 * FTC P2Pool Implementation
 * Decentralized mining - no central pool operator
 */

#include "p2pool.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include "../../node/full_node.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*==============================================================================
 * PPLNS IMPLEMENTATION
 *============================================================================*/

static ftc_pplns_t* pplns_new(int window_size)
{
    ftc_pplns_t* pplns = calloc(1, sizeof(ftc_pplns_t));
    if (!pplns) return NULL;

    pplns->share_capacity = window_size;
    pplns->shares = calloc(window_size, sizeof(ftc_share_t));
    if (!pplns->shares) {
        free(pplns);
        return NULL;
    }

    pplns->miner_capacity = 64;
    pplns->miners = calloc(pplns->miner_capacity, sizeof(ftc_pplns_entry_t));
    if (!pplns->miners) {
        free(pplns->shares);
        free(pplns);
        return NULL;
    }

    return pplns;
}

static void pplns_free(ftc_pplns_t* pplns)
{
    if (!pplns) return;
    free(pplns->shares);
    free(pplns->miners);
    free(pplns);
}

static ftc_pplns_entry_t* pplns_find_miner(ftc_pplns_t* pplns, const char* address)
{
    for (int i = 0; i < pplns->miner_count; i++) {
        if (strcmp(pplns->miners[i].address, address) == 0) {
            return &pplns->miners[i];
        }
    }
    return NULL;
}

static ftc_pplns_entry_t* pplns_add_miner(ftc_pplns_t* pplns, const char* address)
{
    /* Check if already exists */
    ftc_pplns_entry_t* existing = pplns_find_miner(pplns, address);
    if (existing) return existing;

    /* Expand if needed */
    if (pplns->miner_count >= pplns->miner_capacity) {
        int new_cap = pplns->miner_capacity * 2;
        ftc_pplns_entry_t* new_miners = realloc(pplns->miners,
            new_cap * sizeof(ftc_pplns_entry_t));
        if (!new_miners) return NULL;
        pplns->miners = new_miners;
        pplns->miner_capacity = new_cap;
    }

    /* Add new miner */
    ftc_pplns_entry_t* miner = &pplns->miners[pplns->miner_count++];
    memset(miner, 0, sizeof(*miner));
    snprintf(miner->address, sizeof(miner->address), "%s", address);
    return miner;
}

static void pplns_add_share(ftc_pplns_t* pplns, const ftc_share_t* share)
{
    /* Remove old share's contribution if buffer is full */
    if (pplns->share_count >= pplns->share_capacity) {
        ftc_share_t* old = &pplns->shares[pplns->share_head];
        ftc_pplns_entry_t* old_miner = pplns_find_miner(pplns, old->miner_address);
        if (old_miner) {
            old_miner->shares--;
            old_miner->work -= old->work_done;
            pplns->total_work -= old->work_done;
        }
    } else {
        pplns->share_count++;
    }

    /* Add new share */
    pplns->shares[pplns->share_head] = *share;
    pplns->share_head = (pplns->share_head + 1) % pplns->share_capacity;

    /* Update miner stats */
    ftc_pplns_entry_t* miner = pplns_add_miner(pplns, share->miner_address);
    if (miner) {
        miner->shares++;
        miner->work += share->work_done;
        pplns->total_work += share->work_done;
    }
}

static void pplns_recalculate(ftc_pplns_t* pplns)
{
    /* Reset miner stats */
    for (int i = 0; i < pplns->miner_count; i++) {
        pplns->miners[i].shares = 0;
        pplns->miners[i].work = 0;
    }
    pplns->total_work = 0;

    /* Recalculate from shares */
    time_t now = time(NULL);
    for (int i = 0; i < pplns->share_count; i++) {
        int idx = (pplns->share_head - pplns->share_count + i + pplns->share_capacity)
                  % pplns->share_capacity;
        ftc_share_t* share = &pplns->shares[idx];

        /* Skip expired shares */
        if (now - share->timestamp > FTC_P2POOL_SHARE_EXPIRY) continue;

        ftc_pplns_entry_t* miner = pplns_add_miner(pplns, share->miner_address);
        if (miner) {
            miner->shares++;
            miner->work += share->work_done;
            pplns->total_work += share->work_done;
        }
    }
}

/*==============================================================================
 * P2POOL CORE
 *============================================================================*/

ftc_p2pool_t* ftc_p2pool_new(void* node)
{
    ftc_p2pool_t* p2pool = calloc(1, sizeof(ftc_p2pool_t));
    if (!p2pool) return NULL;

    p2pool->node = node;
    p2pool->share_target = FTC_P2POOL_SHARE_TARGET;
    p2pool->pplns_window = FTC_P2POOL_SHARE_WINDOW;
    p2pool->min_payout = FTC_P2POOL_MIN_PAYOUT;
    p2pool->start_time = time(NULL);

    p2pool->pplns = pplns_new(FTC_P2POOL_SHARE_WINDOW);
    if (!p2pool->pplns) {
        free(p2pool);
        return NULL;
    }

    memset(p2pool->best_share, 0, sizeof(p2pool->best_share));

    printf("[P2POOL] Initialized - PPLNS window: %d shares, min payout: %.4f FTC\n",
           p2pool->pplns_window, (double)p2pool->min_payout / 100000000.0);

    return p2pool;
}

void ftc_p2pool_free(ftc_p2pool_t* p2pool)
{
    if (!p2pool) return;
    pplns_free(p2pool->pplns);
    free(p2pool);
}

/*==============================================================================
 * SHARE FUNCTIONS
 *============================================================================*/

void ftc_share_hash(const ftc_share_t* share, ftc_hash256_t out)
{
    /* Hash the share header (version through nonce + miner_address) */
    uint8_t data[256];
    size_t offset = 0;

    memcpy(data + offset, &share->version, 4); offset += 4;
    memcpy(data + offset, share->prev_share, 32); offset += 32;
    memcpy(data + offset, share->block_hash, 32); offset += 32;
    memcpy(data + offset, &share->block_height, 4); offset += 4;
    memcpy(data + offset, &share->timestamp, 4); offset += 4;
    memcpy(data + offset, &share->bits, 4); offset += 4;
    memcpy(data + offset, &share->nonce, 4); offset += 4;

    size_t addr_len = strlen(share->miner_address);
    memcpy(data + offset, share->miner_address, addr_len); offset += addr_len;

    ftc_keccak256(data, offset, out);
}

ftc_share_t* ftc_p2pool_create_share(ftc_p2pool_t* p2pool,
                                      const char* miner_address,
                                      uint32_t block_height,
                                      const ftc_hash256_t block_hash,
                                      uint32_t nonce)
{
    ftc_share_t* share = calloc(1, sizeof(ftc_share_t));
    if (!share) return NULL;

    share->version = FTC_P2POOL_VERSION;
    memcpy(share->prev_share, p2pool->best_share, 32);
    memcpy(share->block_hash, block_hash, 32);
    share->block_height = block_height;
    share->timestamp = (uint32_t)time(NULL);
    share->bits = p2pool->share_target;
    share->nonce = nonce;

    snprintf(share->miner_address, sizeof(share->miner_address), "%s", miner_address);

    /* Estimate work done based on share difficulty */
    ftc_hash256_t target;
    ftc_bits_to_target(share->bits, target);
    /* Work = 2^256 / target (simplified as difficulty * base_work) */
    share->work_done = 1;  /* Each share = 1 unit of work for simplicity */

    /* Compute share hash */
    ftc_share_hash(share, share->hash);

    return share;
}

bool ftc_p2pool_validate_share(ftc_p2pool_t* p2pool, const ftc_share_t* share)
{
    /* Check version */
    if (share->version != FTC_P2POOL_VERSION) {
        return false;
    }

    /* Check timestamp (not too far in future) */
    time_t now = time(NULL);
    if (share->timestamp > now + 120) {
        return false;
    }

    /* Check miner address is valid */
    if (strlen(share->miner_address) < 26 || strlen(share->miner_address) > 62) {
        return false;
    }

    /* Verify hash meets share difficulty */
    ftc_hash256_t computed_hash;
    ftc_share_hash(share, computed_hash);

    if (memcmp(computed_hash, share->hash, 32) != 0) {
        return false;
    }

    ftc_hash256_t target;
    ftc_bits_to_target(share->bits, target);

    /* Compare hash to target (hash must be <= target) */
    for (int i = 31; i >= 0; i--) {
        if (computed_hash[i] < target[i]) break;
        if (computed_hash[i] > target[i]) return false;
    }

    return true;
}

void ftc_p2pool_add_share(ftc_p2pool_t* p2pool, const ftc_share_t* share)
{
    pplns_add_share(p2pool->pplns, share);

    /* Update best share */
    memcpy(p2pool->best_share, share->hash, 32);
    p2pool->share_height++;
    p2pool->total_shares++;

    printf("[P2POOL] Share from %s (total: %llu, miners: %d)\n",
           share->miner_address,
           (unsigned long long)p2pool->total_shares,
           p2pool->pplns->miner_count);
}

bool ftc_p2pool_submit_share(ftc_p2pool_t* p2pool,
                              const char* miner_address,
                              const uint8_t* block_header,
                              uint32_t nonce)
{
    ftc_node_t* node = (ftc_node_t*)p2pool->node;
    if (!node) return false;

    /* Get current block info */
    uint32_t height = node->chain->block_count;
    ftc_hash256_t block_hash;
    ftc_block_hash(node->chain->blocks[node->chain->block_count - 1], block_hash);

    /* Create share */
    ftc_share_t* share = ftc_p2pool_create_share(p2pool, miner_address,
                                                  height, block_hash, nonce);
    if (!share) return false;

    /* Validate */
    if (!ftc_p2pool_validate_share(p2pool, share)) {
        free(share);
        return false;
    }

    /* Add to PPLNS */
    ftc_p2pool_add_share(p2pool, share);

    /* Check if this share also meets block difficulty */
    ftc_hash256_t network_target;
    ftc_bits_to_target(node->chain->blocks[node->chain->block_count - 1]->header.bits,
                       network_target);

    bool is_block = true;
    for (int i = 31; i >= 0; i--) {
        if (share->hash[i] < network_target[i]) break;
        if (share->hash[i] > network_target[i]) {
            is_block = false;
            break;
        }
    }

    if (is_block) {
        printf("[P2POOL] *** BLOCK FOUND by %s at height %u! ***\n",
               miner_address, height);
        p2pool->blocks_found++;
    }

    free(share);
    return true;
}

/*==============================================================================
 * PAYOUT CALCULATION
 *============================================================================*/

ftc_payout_t* ftc_p2pool_get_payouts(ftc_p2pool_t* p2pool,
                                      uint64_t block_reward,
                                      int* payout_count)
{
    *payout_count = 0;

    ftc_pplns_t* pplns = p2pool->pplns;
    if (pplns->miner_count == 0 || pplns->total_work == 0) {
        return NULL;
    }

    /* Recalculate to remove expired shares */
    pplns_recalculate(pplns);

    if (pplns->total_work == 0) {
        return NULL;
    }

    /* Allocate payout array */
    ftc_payout_t* payouts = calloc(pplns->miner_count, sizeof(ftc_payout_t));
    if (!payouts) return NULL;

    int count = 0;
    uint64_t total_paid = 0;

    for (int i = 0; i < pplns->miner_count; i++) {
        ftc_pplns_entry_t* miner = &pplns->miners[i];
        if (miner->work == 0) continue;

        /* Calculate proportional reward */
        uint64_t amount = (block_reward * miner->work) / pplns->total_work;

        /* Skip if below minimum */
        if (amount < p2pool->min_payout) continue;

        /* Add payout */
        snprintf(payouts[count].address, sizeof(payouts[count].address), "%s", miner->address);
        payouts[count].amount = amount;
        total_paid += amount;
        count++;
    }

    /* Distribute any remainder to first miner (largest share holder) */
    if (count > 0 && total_paid < block_reward) {
        payouts[0].amount += block_reward - total_paid;
    }

    *payout_count = count;
    return payouts;
}

ftc_tx_t* ftc_p2pool_create_coinbase(ftc_p2pool_t* p2pool,
                                      uint32_t height,
                                      uint64_t block_reward,
                                      uint64_t fees)
{
    uint64_t total_reward = block_reward + fees;

    /* Get payouts */
    int payout_count = 0;
    ftc_payout_t* payouts = ftc_p2pool_get_payouts(p2pool, total_reward, &payout_count);

    if (payout_count == 0) {
        printf("[P2POOL] Warning: No miners to pay, using fallback\n");
        free(payouts);
        return NULL;
    }

    /* Create coinbase with P2Pool marker */
    const char* marker = "/FTC-P2Pool/";
    ftc_tx_t* tx = ftc_tx_create_coinbase(height, 0, (const uint8_t*)marker, strlen(marker));
    if (!tx) {
        free(payouts);
        return NULL;
    }

    /* Remove the placeholder output (created by ftc_tx_create_coinbase) */
    free(tx->outputs);
    tx->outputs = NULL;
    tx->output_count = 0;

    /* Add outputs for each PPLNS payout */
    for (int i = 0; i < payout_count && i < FTC_P2POOL_MAX_OUTPUTS; i++) {
        /* Decode address to get pubkey_hash */
        ftc_address_t pubkey_hash;
        bool is_mainnet;
        if (ftc_address_decode(payouts[i].address, pubkey_hash, &is_mainnet)) {
            ftc_tx_add_output(tx, payouts[i].amount, pubkey_hash);
        }
    }

    /* Verify we added at least one output */
    if (tx->output_count == 0) {
        printf("[P2POOL] Error: Failed to add any outputs\n");
        ftc_tx_free(tx);
        free(payouts);
        return NULL;
    }

    printf("[P2POOL] Created coinbase with %d outputs (reward: %.4f FTC)\n",
           tx->output_count, (double)total_reward / 100000000.0);

    free(payouts);
    return tx;
}

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

uint32_t ftc_p2pool_get_share_target(ftc_p2pool_t* p2pool)
{
    return p2pool->share_target;
}

void ftc_p2pool_get_stats(ftc_p2pool_t* p2pool, ftc_p2pool_stats_t* stats)
{
    memset(stats, 0, sizeof(*stats));

    stats->total_shares = p2pool->total_shares;
    stats->blocks_found = p2pool->blocks_found;
    stats->uptime = time(NULL) - p2pool->start_time;

    /* Count active miners (with recent shares) */
    pplns_recalculate(p2pool->pplns);
    for (int i = 0; i < p2pool->pplns->miner_count; i++) {
        if (p2pool->pplns->miners[i].shares > 0) {
            stats->active_miners++;
        }
    }

    /* Estimate hashrate from share rate */
    if (stats->uptime > 0) {
        /* shares_per_second * share_difficulty = hashrate */
        double shares_per_sec = (double)p2pool->total_shares / stats->uptime;
        /* Simplified: assume share difficulty of 1 */
        stats->pool_hashrate = (uint64_t)(shares_per_sec * 65536);
    }
}

/*==============================================================================
 * SERIALIZATION
 *============================================================================*/

size_t ftc_share_serialize(const ftc_share_t* share, uint8_t* out, size_t out_size)
{
    size_t needed = 4 + 32 + 32 + 4 + 4 + 4 + 4 + 64 + 8 + 32 + 1;
    if (!out) return needed;
    if (out_size < needed) return 0;

    size_t offset = 0;

    memcpy(out + offset, &share->version, 4); offset += 4;
    memcpy(out + offset, share->prev_share, 32); offset += 32;
    memcpy(out + offset, share->block_hash, 32); offset += 32;
    memcpy(out + offset, &share->block_height, 4); offset += 4;
    memcpy(out + offset, &share->timestamp, 4); offset += 4;
    memcpy(out + offset, &share->bits, 4); offset += 4;
    memcpy(out + offset, &share->nonce, 4); offset += 4;
    memcpy(out + offset, share->miner_address, 64); offset += 64;
    memcpy(out + offset, &share->work_done, 8); offset += 8;
    memcpy(out + offset, share->hash, 32); offset += 32;
    out[offset++] = share->is_block ? 1 : 0;

    return offset;
}

ftc_share_t* ftc_share_deserialize(const uint8_t* data, size_t len)
{
    if (len < 4 + 32 + 32 + 4 + 4 + 4 + 4 + 64 + 8 + 32 + 1) return NULL;

    ftc_share_t* share = calloc(1, sizeof(ftc_share_t));
    if (!share) return NULL;

    size_t offset = 0;

    memcpy(&share->version, data + offset, 4); offset += 4;
    memcpy(share->prev_share, data + offset, 32); offset += 32;
    memcpy(share->block_hash, data + offset, 32); offset += 32;
    memcpy(&share->block_height, data + offset, 4); offset += 4;
    memcpy(&share->timestamp, data + offset, 4); offset += 4;
    memcpy(&share->bits, data + offset, 4); offset += 4;
    memcpy(&share->nonce, data + offset, 4); offset += 4;
    memcpy(share->miner_address, data + offset, 64); offset += 64;
    memcpy(&share->work_done, data + offset, 8); offset += 8;
    memcpy(share->hash, data + offset, 32); offset += 32;
    share->is_block = data[offset++] != 0;

    return share;
}
