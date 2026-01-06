/**
 * FTC Wallet
 *
 * Key management and transaction creation
 */

#ifndef FTC_WALLET_H
#define FTC_WALLET_H

#include "../include/ftc.h"
#include "../crypto/keys.h"
#include "../core/tx.h"
#include "../core/utxo.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_WALLET_MAX_KEYS     1000
#define FTC_WALLET_FILE         "wallet.dat"
#define FTC_WALLET_MAGIC        0x46544357  /* "FTCW" */

/*==============================================================================
 * KEY ENTRY
 *============================================================================*/

typedef struct {
    ftc_privkey_t   privkey;
    ftc_pubkey_t    pubkey;
    ftc_address_t   address;
    char            label[64];
    int64_t         created_at;
    bool            is_change;      /* Change address */
    bool            is_used;        /* Has received funds */
} ftc_wallet_key_t;

/*==============================================================================
 * WALLET STRUCTURE
 *============================================================================*/

typedef struct {
    /* Keys */
    ftc_wallet_key_t*   keys;
    int                 key_count;
    int                 key_capacity;

    /* Default receiving address index */
    int                 default_key;

    /* UTXO tracking */
    ftc_utxo_t**        utxos;
    int                 utxo_count;
    int                 utxo_capacity;

    /* Totals */
    uint64_t            balance;
    uint64_t            pending_balance;

    /* File path */
    char                filepath[256];
    bool                encrypted;

} ftc_wallet_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create new wallet
 */
ftc_wallet_t* ftc_wallet_new(void);

/**
 * Free wallet
 */
void ftc_wallet_free(ftc_wallet_t* wallet);

/**
 * Load wallet from file
 */
ftc_wallet_t* ftc_wallet_load(const char* filepath);

/**
 * Save wallet to file
 */
bool ftc_wallet_save(ftc_wallet_t* wallet, const char* filepath);

/**
 * Generate a new key
 */
ftc_wallet_key_t* ftc_wallet_new_key(ftc_wallet_t* wallet, const char* label);

/**
 * Get default receiving address
 */
bool ftc_wallet_get_address(ftc_wallet_t* wallet, ftc_address_t address);

/**
 * Get address as string
 */
bool ftc_wallet_get_address_str(ftc_wallet_t* wallet, char* addr_str, size_t len);

/**
 * Find key by address
 */
ftc_wallet_key_t* ftc_wallet_find_key(ftc_wallet_t* wallet, const ftc_address_t address);

/**
 * Import private key (WIF format)
 */
ftc_wallet_key_t* ftc_wallet_import_wif(ftc_wallet_t* wallet, const char* wif, const char* label);

/**
 * Export private key (WIF format)
 */
bool ftc_wallet_export_wif(ftc_wallet_t* wallet, const ftc_address_t address, char* wif, size_t len);

/*==============================================================================
 * UTXO MANAGEMENT
 *============================================================================*/

/**
 * Add UTXO to wallet
 */
bool ftc_wallet_add_utxo(ftc_wallet_t* wallet, const ftc_utxo_t* utxo);

/**
 * Remove UTXO (spent)
 */
bool ftc_wallet_remove_utxo(ftc_wallet_t* wallet, const ftc_hash256_t txid, uint32_t vout);

/**
 * Get wallet balance
 */
uint64_t ftc_wallet_get_balance(ftc_wallet_t* wallet);

/**
 * Select UTXOs for spending
 */
int ftc_wallet_select_utxos(
    ftc_wallet_t* wallet,
    uint64_t amount,
    ftc_utxo_t** selected,
    int max_count,
    uint64_t* total
);

/*==============================================================================
 * TRANSACTION CREATION
 *============================================================================*/

/**
 * Create a simple payment transaction
 */
ftc_tx_t* ftc_wallet_create_tx(
    ftc_wallet_t* wallet,
    const ftc_address_t to,
    uint64_t amount,
    uint64_t fee
);

/**
 * Sign transaction inputs belonging to wallet
 */
bool ftc_wallet_sign_tx(ftc_wallet_t* wallet, ftc_tx_t* tx);

/**
 * Create and sign transaction
 */
ftc_tx_t* ftc_wallet_send(
    ftc_wallet_t* wallet,
    const ftc_address_t to,
    uint64_t amount,
    uint64_t fee
);

/*==============================================================================
 * BLOCKCHAIN SCANNING
 *============================================================================*/

/**
 * Check if transaction affects wallet
 */
bool ftc_wallet_is_mine(ftc_wallet_t* wallet, const ftc_tx_t* tx);

/**
 * Process incoming transaction
 */
void ftc_wallet_process_tx(ftc_wallet_t* wallet, const ftc_tx_t* tx, uint32_t height);

/**
 * Process incoming block
 */
void ftc_wallet_process_block(ftc_wallet_t* wallet, const ftc_block_t* block, uint32_t height);

#ifdef __cplusplus
}
#endif

#endif /* FTC_WALLET_H */
