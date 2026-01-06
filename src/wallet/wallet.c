/**
 * FTC Wallet Implementation
 */

#include "wallet.h"
#include "../crypto/keccak256.h"
#include "../core/block.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*==============================================================================
 * WALLET CREATION
 *============================================================================*/

ftc_wallet_t* ftc_wallet_new(void)
{
    ftc_wallet_t* wallet = (ftc_wallet_t*)calloc(1, sizeof(ftc_wallet_t));
    if (!wallet) return NULL;

    wallet->key_capacity = 16;
    wallet->keys = (ftc_wallet_key_t*)calloc(wallet->key_capacity, sizeof(ftc_wallet_key_t));
    if (!wallet->keys) {
        free(wallet);
        return NULL;
    }

    wallet->utxo_capacity = 64;
    wallet->utxos = (ftc_utxo_t**)calloc(wallet->utxo_capacity, sizeof(ftc_utxo_t*));
    if (!wallet->utxos) {
        free(wallet->keys);
        free(wallet);
        return NULL;
    }

    wallet->default_key = -1;
    return wallet;
}

void ftc_wallet_free(ftc_wallet_t* wallet)
{
    if (!wallet) return;

    /* Securely zero private keys */
    if (wallet->keys) {
        for (int i = 0; i < wallet->key_count; i++) {
            memset(wallet->keys[i].privkey, 0, 32);
        }
        free(wallet->keys);
    }

    if (wallet->utxos) {
        for (int i = 0; i < wallet->utxo_count; i++) {
            free(wallet->utxos[i]);
        }
        free(wallet->utxos);
    }

    free(wallet);
}

/*==============================================================================
 * KEY MANAGEMENT
 *============================================================================*/

ftc_wallet_key_t* ftc_wallet_new_key(ftc_wallet_t* wallet, const char* label)
{
    if (wallet->key_count >= FTC_WALLET_MAX_KEYS) {
        return NULL;
    }

    /* Expand if needed */
    if (wallet->key_count >= wallet->key_capacity) {
        int new_cap = wallet->key_capacity * 2;
        ftc_wallet_key_t* new_keys = (ftc_wallet_key_t*)realloc(
            wallet->keys, new_cap * sizeof(ftc_wallet_key_t));
        if (!new_keys) return NULL;
        wallet->keys = new_keys;
        wallet->key_capacity = new_cap;
    }

    ftc_wallet_key_t* key = &wallet->keys[wallet->key_count];
    memset(key, 0, sizeof(*key));

    /* Generate keypair */
    if (!ftc_keypair_generate(key->privkey, key->pubkey)) {
        return NULL;
    }

    /* Derive address */
    ftc_address_from_pubkey(key->pubkey, key->address);

    /* Set metadata */
    if (label) {
        strncpy(key->label, label, sizeof(key->label) - 1);
    }
    key->created_at = time(NULL);

    wallet->key_count++;

    /* Set as default if first key */
    if (wallet->default_key < 0) {
        wallet->default_key = wallet->key_count - 1;
    }

    return key;
}

bool ftc_wallet_get_address(ftc_wallet_t* wallet, ftc_address_t address)
{
    if (!wallet || wallet->key_count == 0) return false;

    int idx = wallet->default_key >= 0 ? wallet->default_key : 0;
    memcpy(address, wallet->keys[idx].address, 20);
    return true;
}

bool ftc_wallet_get_address_str(ftc_wallet_t* wallet, char* addr_str, size_t len)
{
    if (!wallet || wallet->key_count == 0 || len < 40) return false;

    ftc_address_t address;
    if (!ftc_wallet_get_address(wallet, address)) return false;

    ftc_address_encode(address, true, addr_str);
    return true;
}

ftc_wallet_key_t* ftc_wallet_find_key(ftc_wallet_t* wallet, const ftc_address_t address)
{
    for (int i = 0; i < wallet->key_count; i++) {
        if (memcmp(wallet->keys[i].address, address, 20) == 0) {
            return &wallet->keys[i];
        }
    }
    return NULL;
}

ftc_wallet_key_t* ftc_wallet_import_wif(ftc_wallet_t* wallet, const char* wif, const char* label)
{
    if (wallet->key_count >= FTC_WALLET_MAX_KEYS) {
        return NULL;
    }

    /* Expand if needed */
    if (wallet->key_count >= wallet->key_capacity) {
        int new_cap = wallet->key_capacity * 2;
        ftc_wallet_key_t* new_keys = (ftc_wallet_key_t*)realloc(
            wallet->keys, new_cap * sizeof(ftc_wallet_key_t));
        if (!new_keys) return NULL;
        wallet->keys = new_keys;
        wallet->key_capacity = new_cap;
    }

    ftc_wallet_key_t* key = &wallet->keys[wallet->key_count];
    memset(key, 0, sizeof(*key));

    /* Decode WIF */
    bool mainnet;
    if (!ftc_privkey_from_wif(wif, key->privkey, &mainnet)) {
        return NULL;
    }

    /* Derive pubkey and address */
    ftc_pubkey_from_privkey(key->privkey, key->pubkey);
    ftc_address_from_pubkey(key->pubkey, key->address);

    /* Set metadata */
    if (label) {
        strncpy(key->label, label, sizeof(key->label) - 1);
    }
    key->created_at = time(NULL);

    wallet->key_count++;
    return key;
}

bool ftc_wallet_export_wif(ftc_wallet_t* wallet, const ftc_address_t address, char* wif, size_t len)
{
    if (len < 52) return false;

    ftc_wallet_key_t* key = ftc_wallet_find_key(wallet, address);
    if (!key) return false;

    ftc_privkey_to_wif(key->privkey, true, wif);
    return true;
}

/*==============================================================================
 * UTXO MANAGEMENT
 *============================================================================*/

bool ftc_wallet_add_utxo(ftc_wallet_t* wallet, const ftc_utxo_t* utxo)
{
    /* Check if we own this address */
    if (!ftc_wallet_find_key(wallet, utxo->pubkey_hash)) {
        return false;
    }

    /* Check if already exists */
    for (int i = 0; i < wallet->utxo_count; i++) {
        if (memcmp(wallet->utxos[i]->txid, utxo->txid, 32) == 0 &&
            wallet->utxos[i]->vout == utxo->vout) {
            return true;  /* Already have it */
        }
    }

    /* Expand if needed */
    if (wallet->utxo_count >= wallet->utxo_capacity) {
        int new_cap = wallet->utxo_capacity * 2;
        ftc_utxo_t** new_utxos = (ftc_utxo_t**)realloc(
            wallet->utxos, new_cap * sizeof(ftc_utxo_t*));
        if (!new_utxos) return false;
        wallet->utxos = new_utxos;
        wallet->utxo_capacity = new_cap;
    }

    ftc_utxo_t* copy = (ftc_utxo_t*)malloc(sizeof(ftc_utxo_t));
    if (!copy) return false;
    memcpy(copy, utxo, sizeof(*utxo));

    wallet->utxos[wallet->utxo_count++] = copy;
    wallet->balance += utxo->value;

    return true;
}

bool ftc_wallet_remove_utxo(ftc_wallet_t* wallet, const ftc_hash256_t txid, uint32_t vout)
{
    for (int i = 0; i < wallet->utxo_count; i++) {
        if (memcmp(wallet->utxos[i]->txid, txid, 32) == 0 &&
            wallet->utxos[i]->vout == vout) {

            wallet->balance -= wallet->utxos[i]->value;
            free(wallet->utxos[i]);

            /* Shift remaining */
            for (int j = i; j < wallet->utxo_count - 1; j++) {
                wallet->utxos[j] = wallet->utxos[j + 1];
            }
            wallet->utxo_count--;
            return true;
        }
    }
    return false;
}

uint64_t ftc_wallet_get_balance(ftc_wallet_t* wallet)
{
    return wallet->balance;
}

int ftc_wallet_select_utxos(
    ftc_wallet_t* wallet,
    uint64_t amount,
    ftc_utxo_t** selected,
    int max_count,
    uint64_t* total)
{
    *total = 0;
    int count = 0;

    /* Simple greedy selection - select largest first */
    /* In production, use more sophisticated coin selection */

    /* Sort by value (bubble sort for simplicity) */
    for (int i = 0; i < wallet->utxo_count - 1; i++) {
        for (int j = 0; j < wallet->utxo_count - i - 1; j++) {
            if (wallet->utxos[j]->value < wallet->utxos[j + 1]->value) {
                ftc_utxo_t* temp = wallet->utxos[j];
                wallet->utxos[j] = wallet->utxos[j + 1];
                wallet->utxos[j + 1] = temp;
            }
        }
    }

    /* Select UTXOs until we have enough */
    for (int i = 0; i < wallet->utxo_count && count < max_count; i++) {
        if (!wallet->utxos[i]->spent) {
            selected[count++] = wallet->utxos[i];
            *total += wallet->utxos[i]->value;

            if (*total >= amount) break;
        }
    }

    return count;
}

/*==============================================================================
 * TRANSACTION CREATION
 *============================================================================*/

ftc_tx_t* ftc_wallet_create_tx(
    ftc_wallet_t* wallet,
    const ftc_address_t to,
    uint64_t amount,
    uint64_t fee)
{
    uint64_t needed = amount + fee;

    /* Select UTXOs */
    ftc_utxo_t* selected[100];
    uint64_t total;
    int input_count = ftc_wallet_select_utxos(wallet, needed, selected, 100, &total);

    if (total < needed) {
        return NULL;  /* Insufficient funds */
    }

    /* Create transaction */
    ftc_tx_t* tx = ftc_tx_new();
    if (!tx) return NULL;

    /* Add inputs */
    for (int i = 0; i < input_count; i++) {
        ftc_tx_add_input(tx, selected[i]->txid, selected[i]->vout);
    }

    /* Add output to recipient */
    ftc_tx_add_output(tx, amount, to);

    /* Add change output if needed */
    uint64_t change = total - amount - fee;
    if (change > 0) {
        /* Use first key's address as change address */
        /* In production, generate new change address */
        ftc_tx_add_output(tx, change, wallet->keys[0].address);
    }

    return tx;
}

bool ftc_wallet_sign_tx(ftc_wallet_t* wallet, ftc_tx_t* tx)
{
    /* For each input, find the key and sign */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        /* Find UTXO being spent */
        ftc_utxo_t* utxo = NULL;
        for (int j = 0; j < wallet->utxo_count; j++) {
            if (memcmp(wallet->utxos[j]->txid, tx->inputs[i].prev_txid, 32) == 0 &&
                wallet->utxos[j]->vout == tx->inputs[i].prev_index) {
                utxo = wallet->utxos[j];
                break;
            }
        }

        if (!utxo) {
            return false;  /* Can't find UTXO */
        }

        /* Find key for this address */
        ftc_wallet_key_t* key = ftc_wallet_find_key(wallet, utxo->pubkey_hash);
        if (!key) {
            return false;  /* Not our key */
        }

        /* Sign input */
        if (!ftc_tx_sign_input(tx, i, key->privkey, key->pubkey)) {
            return false;
        }
    }

    return true;
}

ftc_tx_t* ftc_wallet_send(
    ftc_wallet_t* wallet,
    const ftc_address_t to,
    uint64_t amount,
    uint64_t fee)
{
    ftc_tx_t* tx = ftc_wallet_create_tx(wallet, to, amount, fee);
    if (!tx) return NULL;

    if (!ftc_wallet_sign_tx(wallet, tx)) {
        ftc_tx_free(tx);
        return NULL;
    }

    return tx;
}

/*==============================================================================
 * BLOCKCHAIN SCANNING
 *============================================================================*/

bool ftc_wallet_is_mine(ftc_wallet_t* wallet, const ftc_tx_t* tx)
{
    /* Check outputs */
    for (uint32_t i = 0; i < tx->output_count; i++) {
        if (ftc_wallet_find_key(wallet, tx->outputs[i].pubkey_hash)) {
            return true;
        }
    }

    /* Check inputs (for spending detection) */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        for (int j = 0; j < wallet->utxo_count; j++) {
            if (memcmp(wallet->utxos[j]->txid, tx->inputs[i].prev_txid, 32) == 0 &&
                wallet->utxos[j]->vout == tx->inputs[i].prev_index) {
                return true;
            }
        }
    }

    return false;
}

void ftc_wallet_process_tx(ftc_wallet_t* wallet, const ftc_tx_t* tx, uint32_t height)
{
    ftc_hash256_t txid;
    ftc_tx_hash(tx, txid);

    /* Check for received outputs */
    for (uint32_t i = 0; i < tx->output_count; i++) {
        ftc_wallet_key_t* key = ftc_wallet_find_key(wallet, tx->outputs[i].pubkey_hash);
        if (key) {
            key->is_used = true;

            ftc_utxo_t utxo;
            memcpy(utxo.txid, txid, 32);
            utxo.vout = i;
            utxo.value = tx->outputs[i].value;
            memcpy(utxo.pubkey_hash, tx->outputs[i].pubkey_hash, 20);
            utxo.height = height;
            utxo.spent = false;
            memset(utxo.spent_txid, 0, 32);
            utxo.spent_vin = 0;

            ftc_wallet_add_utxo(wallet, &utxo);
        }
    }

    /* Check for spent inputs */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        ftc_wallet_remove_utxo(wallet, tx->inputs[i].prev_txid, tx->inputs[i].prev_index);
    }
}

void ftc_wallet_process_block(ftc_wallet_t* wallet, const ftc_block_t* block, uint32_t height)
{
    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_wallet_process_tx(wallet, block->txs[i], height);
    }
}

/*==============================================================================
 * FILE I/O
 *============================================================================*/

ftc_wallet_t* ftc_wallet_load(const char* filepath)
{
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;

    /* Read header */
    uint32_t magic;
    if (fread(&magic, 4, 1, f) != 1 || magic != FTC_WALLET_MAGIC) {
        fclose(f);
        return NULL;
    }

    ftc_wallet_t* wallet = ftc_wallet_new();
    if (!wallet) {
        fclose(f);
        return NULL;
    }

    strncpy(wallet->filepath, filepath, sizeof(wallet->filepath) - 1);

    /* Read key count */
    uint32_t key_count;
    if (fread(&key_count, 4, 1, f) != 1) {
        ftc_wallet_free(wallet);
        fclose(f);
        return NULL;
    }

    /* Read keys */
    for (uint32_t i = 0; i < key_count; i++) {
        ftc_wallet_key_t key;
        memset(&key, 0, sizeof(key));

        if (fread(key.privkey, 32, 1, f) != 1 ||
            fread(key.label, 64, 1, f) != 1 ||
            fread(&key.created_at, 8, 1, f) != 1 ||
            fread(&key.is_change, 1, 1, f) != 1) {
            ftc_wallet_free(wallet);
            fclose(f);
            return NULL;
        }

        /* Derive pubkey and address from privkey */
        ftc_pubkey_from_privkey(key.privkey, key.pubkey);
        ftc_address_from_pubkey(key.pubkey, key.address);

        /* Add to wallet */
        if (wallet->key_count >= wallet->key_capacity) {
            int new_cap = wallet->key_capacity * 2;
            wallet->keys = (ftc_wallet_key_t*)realloc(
                wallet->keys, new_cap * sizeof(ftc_wallet_key_t));
            wallet->key_capacity = new_cap;
        }
        wallet->keys[wallet->key_count++] = key;
    }

    if (wallet->key_count > 0) {
        wallet->default_key = 0;
    }

    /* Read UTXOs */
    uint32_t utxo_count;
    if (fread(&utxo_count, 4, 1, f) == 1) {
        for (uint32_t i = 0; i < utxo_count; i++) {
            ftc_utxo_t utxo;
            if (fread(&utxo, sizeof(utxo), 1, f) != 1) break;

            if (!utxo.spent) {
                ftc_wallet_add_utxo(wallet, &utxo);
            }
        }
    }

    fclose(f);
    return wallet;
}

bool ftc_wallet_save(ftc_wallet_t* wallet, const char* filepath)
{
    const char* path = filepath ? filepath : wallet->filepath;
    if (!path[0]) return false;

    FILE* f = fopen(path, "wb");
    if (!f) return false;

    /* Write header */
    uint32_t magic = FTC_WALLET_MAGIC;
    fwrite(&magic, 4, 1, f);

    /* Write key count */
    uint32_t key_count = wallet->key_count;
    fwrite(&key_count, 4, 1, f);

    /* Write keys (only privkey, label, metadata) */
    for (int i = 0; i < wallet->key_count; i++) {
        fwrite(wallet->keys[i].privkey, 32, 1, f);
        fwrite(wallet->keys[i].label, 64, 1, f);
        fwrite(&wallet->keys[i].created_at, 8, 1, f);
        fwrite(&wallet->keys[i].is_change, 1, 1, f);
    }

    /* Write UTXOs */
    uint32_t utxo_count = wallet->utxo_count;
    fwrite(&utxo_count, 4, 1, f);

    for (int i = 0; i < wallet->utxo_count; i++) {
        fwrite(wallet->utxos[i], sizeof(ftc_utxo_t), 1, f);
    }

    fclose(f);

    if (filepath) {
        strncpy(wallet->filepath, filepath, sizeof(wallet->filepath) - 1);
    }

    return true;
}
