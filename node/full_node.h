/**
 * FTC Full Node
 *
 * Main node that combines all components
 */

#ifndef FTC_FULL_NODE_H
#define FTC_FULL_NODE_H

#include "../include/ftc.h"
#include "../src/core/block.h"
#include "../src/core/tx.h"
#include "../src/core/mempool.h"
#include "../src/core/consensus.h"
#include "../src/network/p2p.h"
#include "../src/rpc/rpc.h"
#include "../src/wallet/wallet.h"

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION ftc_mutex_t;
#define FTC_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define FTC_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define FTC_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define FTC_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
typedef pthread_mutex_t ftc_mutex_t;
static inline void ftc_mutex_init_recursive(pthread_mutex_t* m) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
}
#define FTC_MUTEX_INIT(m) ftc_mutex_init_recursive(&(m))
#define FTC_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define FTC_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define FTC_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_NODE_VERSION        "2.1.0"
#define FTC_DATA_DIR            "ftcdata"
#define FTC_BLOCKS_FILE         "blocks.dat"
#define FTC_CHAIN_FILE          "chain.dat"

/*==============================================================================
 * NODE CONFIGURATION
 *============================================================================*/

typedef struct {
    /* Network */
    uint16_t        p2p_port;
    uint16_t        rpc_port;
    bool            listen;
    bool            testnet;

    /* Data */
    char            data_dir[256];

    /* Wallet */
    bool            wallet_enabled;

    /* Seeds */
    const char**    seeds;
    int             seed_count;

    /* Logging */
    int             log_level;

} ftc_node_config_t;

/*==============================================================================
 * BLOCKCHAIN STATE
 *============================================================================*/

/* Hash index for O(1) block lookups */
#define FTC_HASH_INDEX_SIZE 8192  /* Must be power of 2 */

typedef struct ftc_hash_entry {
    ftc_hash256_t           hash;
    int                     block_index;  /* Index into blocks array */
    struct ftc_hash_entry*  next;         /* For collision chaining */
} ftc_hash_entry_t;

typedef struct {
    /* Block storage (simple in-memory for now) */
    ftc_block_t**   blocks;
    int             block_count;
    int             block_capacity;

    /* Hash index for O(1) lookups */
    ftc_hash_entry_t* hash_index[FTC_HASH_INDEX_SIZE];

    /* Best chain */
    ftc_hash256_t   best_hash;
    uint32_t        best_height;
    uint64_t        total_work;

    /* Genesis */
    ftc_block_t*    genesis;

    /* Thread safety */
    ftc_mutex_t     mutex;

    /* Persistence protection: don't save if we have fewer blocks than loaded */
    uint32_t        loaded_block_count;

} ftc_chain_t;

/*==============================================================================
 * FULL NODE
 *============================================================================*/

typedef struct {
    /* Configuration */
    ftc_node_config_t   config;

    /* Components */
    ftc_chain_t*        chain;
    ftc_mempool_t*      mempool;
    ftc_p2p_t*          p2p;
    ftc_rpc_server_t*   rpc;
    ftc_wallet_t*       wallet;

    /* UTXO set */
    ftc_utxo_set_t*     utxo_set;

    /* State */
    bool                running;
    bool                syncing;
    int64_t             start_time;

    /* Dashboard stats */
    int64_t             last_dashboard_update;
    int64_t             last_block_time;
    uint32_t            blocks_received;
    uint32_t            prev_height;

    /* Auto-save state */
    uint32_t            last_save_height;

} ftc_node_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create node with configuration
 */
ftc_node_t* ftc_node_new(const ftc_node_config_t* config);

/**
 * Free node
 */
void ftc_node_free(ftc_node_t* node);

/**
 * Initialize default configuration
 */
void ftc_node_config_default(ftc_node_config_t* config);

/**
 * Start the node
 */
bool ftc_node_start(ftc_node_t* node);

/**
 * Stop the node
 */
void ftc_node_stop(ftc_node_t* node);

/**
 * Run main loop (blocking)
 */
void ftc_node_run(ftc_node_t* node);

/**
 * Process one iteration of the main loop
 */
void ftc_node_poll(ftc_node_t* node);

/*==============================================================================
 * BLOCKCHAIN
 *============================================================================*/

/**
 * Initialize chain with genesis block
 */
bool ftc_chain_init(ftc_chain_t* chain);

/**
 * Add block to chain
 */
bool ftc_chain_add_block(ftc_node_t* node, ftc_block_t* block);

/**
 * Get block by hash
 */
ftc_block_t* ftc_chain_get_block(ftc_chain_t* chain, const ftc_hash256_t hash);

/**
 * Get block by height
 */
ftc_block_t* ftc_chain_get_block_at(ftc_chain_t* chain, uint32_t height);

/**
 * Validate block
 */
bool ftc_node_validate_block(ftc_node_t* node, const ftc_block_t* block);

/**
 * Validate transaction
 */
bool ftc_node_validate_tx(ftc_node_t* node, const ftc_tx_t* tx);

/*==============================================================================
 * BLOCK TEMPLATE (for external miners via RPC)
 *============================================================================*/

/**
 * Create block template for mining
 */
ftc_block_t* ftc_node_create_block_template(ftc_node_t* node, const ftc_address_t miner_addr);

/**
 * Submit mined block
 */
bool ftc_node_submit_block(ftc_node_t* node, ftc_block_t* block);

#ifdef __cplusplus
}
#endif

#endif /* FTC_FULL_NODE_H */
