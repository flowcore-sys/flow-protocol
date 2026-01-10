/**
 * Flow Token Chain (FTC) - Public API Header
 *
 * Production-quality GPU-mineable cryptocurrency
 * for decentralized AI compute payments.
 */

#ifndef FTC_H
#define FTC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * VERSION
 *============================================================================*/

#define FTC_VERSION_MAJOR       2
#define FTC_VERSION_MINOR       0
#define FTC_VERSION_PATCH       0
#define FTC_VERSION_STRING      "2.0.0"
#define FTC_PROTOCOL_VERSION    70001

/*==============================================================================
 * NETWORK CONSTANTS
 *============================================================================*/

#define FTC_MAINNET_MAGIC       0x46544300  /* "FTC\0" */
#define FTC_TESTNET_MAGIC       0x66746300  /* "ftc\0" */

#define FTC_MAINNET_PORT        17317
#define FTC_MAINNET_RPC_PORT    17318
#define FTC_TESTNET_PORT        27317
#define FTC_TESTNET_RPC_PORT    27318

#define FTC_RPC_PORT            17318

#define FTC_USER_AGENT          "/FTC:2.1.0/"

/*==============================================================================
 * SUPPLY & REWARDS
 *============================================================================*/

#define FTC_COIN                100000000ULL        /* 10^8 satoshis */
#define FTC_MAX_SUPPLY          (21000000ULL * FTC_COIN)
#define FTC_INITIAL_REWARD      (50ULL * FTC_COIN)
#define FTC_HALVING_INTERVAL    210000
#define FTC_DECIMALS            8

/*==============================================================================
 * TIMING
 *============================================================================*/

#define FTC_TARGET_BLOCK_TIME   60          /* 60 seconds */
#define FTC_DIFFICULTY_INTERVAL 2016        /* Legacy: Retarget every 2016 blocks */
#define FTC_LWMA_WINDOW         144         /* LWMA: Use last 144 blocks (~2.5 hours) for smooth adjustment */
#define FTC_LWMA_ACTIVATION     25000       /* Activate LWMA after this height */
#define FTC_MAX_FUTURE_TIME     7200        /* 2 hours */

/*==============================================================================
 * BLOCK LIMITS
 *============================================================================*/

#define FTC_MAX_BLOCK_SIZE      1000000     /* 1 MB */
#define FTC_MAX_BLOCK_SIGOPS    20000
#define FTC_COINBASE_MATURITY   100

/*==============================================================================
 * TRANSACTION LIMITS
 *============================================================================*/

#define FTC_MIN_TX_FEE          10000       /* 0.0001 FTC */
#define FTC_DUST_THRESHOLD      546
#define FTC_MAX_TX_SIZE         100000      /* 100 KB */

/*==============================================================================
 * GENESIS BLOCK
 *============================================================================*/

#define FTC_GENESIS_TIMESTAMP   1736208000  /* 2025-01-07 00:00:00 UTC */
#define FTC_GENESIS_BITS        0x1e0fffff  /* Initial difficulty */
#define FTC_GENESIS_MESSAGE     "FTC Genesis - Decentralized AI Compute - 2025"
#define FTC_GENESIS_NONCE       697423U     /* Mined nonce */
#define FTC_GENESIS_HASH        "887abb52d6b241f4dfba45d5946278bb3abbb9115bc1ec7423c59a49d80b0000"
#define FTC_GENESIS_MERKLE      "889766c60bd569753091c4662f048633f4cd334c3d2a1eae1808ff589c229b53"

/*==============================================================================
 * ADDRESS PREFIXES
 *============================================================================*/

#define FTC_PUBKEY_ADDRESS      0x00        /* 'F' prefix for mainnet */
#define FTC_SCRIPT_ADDRESS      0x05        /* 'M' prefix */
#define FTC_PRIVKEY_PREFIX      0x80        /* WIF prefix */
#define FTC_TESTNET_PUBKEY      0x6F        /* 'f' prefix for testnet */

/*==============================================================================
 * HASH SIZES
 *============================================================================*/

#define FTC_HASH_SIZE           32
#define FTC_PUBKEY_SIZE         32
#define FTC_PRIVKEY_SIZE        32
#define FTC_SIGNATURE_SIZE      64
#define FTC_ADDRESS_SIZE        20
#define FTC_CHECKSUM_SIZE       4

/*==============================================================================
 * BASIC TYPES
 *============================================================================*/

typedef uint8_t ftc_hash256_t[FTC_HASH_SIZE];
typedef uint8_t ftc_pubkey_t[FTC_PUBKEY_SIZE];
typedef uint8_t ftc_privkey_t[FTC_PRIVKEY_SIZE];
typedef uint8_t ftc_signature_t[FTC_SIGNATURE_SIZE];
typedef uint8_t ftc_address_t[FTC_ADDRESS_SIZE];

/*==============================================================================
 * ERROR CODES
 *============================================================================*/

typedef enum {
    FTC_OK = 0,
    FTC_ERR_INVALID_PARAM,
    FTC_ERR_OUT_OF_MEMORY,
    FTC_ERR_INVALID_HASH,
    FTC_ERR_INVALID_SIGNATURE,
    FTC_ERR_INVALID_BLOCK,
    FTC_ERR_INVALID_TX,
    FTC_ERR_INVALID_UTXO,
    FTC_ERR_DUPLICATE_TX,
    FTC_ERR_DOUBLE_SPEND,
    FTC_ERR_INSUFFICIENT_FUNDS,
    FTC_ERR_INVALID_ADDRESS,
    FTC_ERR_DB_ERROR,
    FTC_ERR_NETWORK_ERROR,
    FTC_ERR_PEER_BANNED,
    FTC_ERR_SYNC_ERROR,
    FTC_ERR_NOT_FOUND,
    FTC_ERR_ALREADY_EXISTS,
    FTC_ERR_CONSENSUS_ERROR,
    FTC_ERR_INVALID_DIFFICULTY,
    FTC_ERR_BLOCK_TOO_OLD,
    FTC_ERR_BLOCK_TOO_NEW
} ftc_error_t;

/*==============================================================================
 * BLOCK HEADER (80 bytes)
 *============================================================================*/

#pragma pack(push, 1)
typedef struct {
    uint32_t        version;            /* 4 bytes  */
    ftc_hash256_t   prev_hash;          /* 32 bytes */
    ftc_hash256_t   merkle_root;        /* 32 bytes */
    uint32_t        timestamp;          /* 4 bytes  */
    uint32_t        bits;               /* 4 bytes (compact difficulty) */
    uint32_t        nonce;              /* 4 bytes  */
} ftc_block_header_t;                   /* Total: 80 bytes */
#pragma pack(pop)

/*==============================================================================
 * TRANSACTION INPUT
 *============================================================================*/

typedef struct {
    ftc_hash256_t   prev_txid;          /* Previous transaction hash */
    uint32_t        vout;               /* Output index */
    ftc_signature_t signature;          /* Ed25519 signature */
    ftc_pubkey_t    pubkey;             /* Ed25519 public key */
} ftc_txin_t;

/* Alias for code using prev_index */
#define prev_index vout

/*==============================================================================
 * TRANSACTION OUTPUT
 *============================================================================*/

typedef struct {
    uint64_t        value;              /* Amount in satoshis */
    ftc_address_t   pubkey_hash;        /* Recipient address (20 bytes) */
} ftc_txout_t;

/*==============================================================================
 * TRANSACTION
 *============================================================================*/

typedef struct {
    uint32_t        version;            /* Transaction version */
    uint32_t        input_count;        /* Number of inputs */
    ftc_txin_t*     inputs;             /* Input array */
    uint32_t        output_count;       /* Number of outputs */
    ftc_txout_t*    outputs;            /* Output array */
    uint32_t        locktime;           /* Block height or timestamp */
} ftc_tx_t;

/*==============================================================================
 * BLOCK
 *============================================================================*/

typedef struct {
    ftc_block_header_t  header;         /* Block header */
    uint32_t            tx_count;       /* Number of transactions */
    ftc_tx_t**          txs;            /* Transaction array (alias: transactions) */
} ftc_block_t;

/* Alias for compatibility */
#define transactions txs

/*==============================================================================
 * UTXO (Unspent Transaction Output)
 *============================================================================*/

typedef struct {
    ftc_hash256_t   txid;               /* Transaction hash */
    uint32_t        vout;               /* Output index */
    uint64_t        value;              /* Amount */
    ftc_address_t   pubkey_hash;        /* Owner address */
    uint32_t        height;             /* Block height when created */
    bool            coinbase;           /* Is coinbase output? */
    bool            spent;              /* Has been spent? */
    ftc_hash256_t   spent_txid;         /* Spending transaction */
    uint32_t        spent_vin;          /* Spending input index */
} ftc_utxo_t;

/*==============================================================================
 * HELPER MACROS
 *============================================================================*/

#define FTC_SATOSHI_TO_COIN(sat)    ((double)(sat) / FTC_COIN)
#define FTC_COIN_TO_SATOSHI(coin)   ((uint64_t)((coin) * FTC_COIN))

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

/**
 * Get block reward for given height
 */
static inline uint64_t ftc_get_block_reward(uint32_t height) {
    uint32_t halvings = height / FTC_HALVING_INTERVAL;
    if (halvings >= 64) return 0;
    return FTC_INITIAL_REWARD >> halvings;
}

/**
 * Check if block is valid checkpoint height
 */
static inline bool ftc_is_difficulty_adjustment(uint32_t height) {
    return (height % FTC_DIFFICULTY_INTERVAL) == 0;
}

/**
 * Calculate total supply at given height
 */
static inline uint64_t ftc_supply_at_height(uint32_t height) {
    uint64_t supply = 0;
    uint64_t reward = FTC_INITIAL_REWARD;
    uint32_t h = 0;

    while (h < height && reward > 0) {
        uint32_t blocks_at_reward = FTC_HALVING_INTERVAL - (h % FTC_HALVING_INTERVAL);
        if (h + blocks_at_reward > height) {
            blocks_at_reward = height - h;
        }
        supply += reward * blocks_at_reward;
        h += blocks_at_reward;
        reward >>= 1;
    }

    return supply;
}

#ifdef __cplusplus
}
#endif

#endif /* FTC_H */
