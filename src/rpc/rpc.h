/**
 * FTC JSON-RPC Server
 *
 * HTTP-based JSON-RPC interface for node interaction
 */

#ifndef FTC_RPC_H
#define FTC_RPC_H

#include "ftc.h"
#include "../core/block.h"
#include "../core/tx.h"
#include "../core/mempool.h"
#include "../core/utxo.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET ftc_rpc_socket_t;
#else
typedef int ftc_rpc_socket_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_RPC_PORT            17318
#define FTC_RPC_MAX_CONNECTIONS 16
#define FTC_RPC_MAX_REQUEST     (1024 * 1024)  /* 1MB */
#define FTC_RPC_MAX_RESPONSE    (4 * 1024 * 1024)  /* 4MB */

/*==============================================================================
 * RPC CONTEXT (passed to handlers)
 *============================================================================*/

typedef struct ftc_rpc_context ftc_rpc_context_t;

/* Callback to get blockchain data */
typedef struct {
    /* Blockchain queries */
    ftc_block_t* (*get_block_by_hash)(void* ctx, const ftc_hash256_t hash);
    ftc_block_t* (*get_block_by_height)(void* ctx, uint32_t height);
    uint32_t (*get_best_height)(void* ctx);
    void (*get_best_hash)(void* ctx, ftc_hash256_t hash);
    double (*get_difficulty)(void* ctx);

    /* Transaction queries */
    ftc_tx_t* (*get_tx)(void* ctx, const ftc_hash256_t txid);
    bool (*send_tx)(void* ctx, ftc_tx_t* tx);

    /* Mempool */
    ftc_mempool_t* (*get_mempool)(void* ctx);

    /* Wallet (optional) */
    bool (*get_balance)(void* ctx, const ftc_address_t addr, uint64_t* balance);
    bool (*get_utxos)(void* ctx, const ftc_address_t addr, ftc_utxo_t** utxos, size_t* count);
    ftc_tx_t* (*create_tx)(void* ctx, const ftc_address_t from, const ftc_address_t to, uint64_t amount, uint64_t fee);

    /* Network */
    int (*get_peer_count)(void* ctx);
    int (*get_connection_count)(void* ctx);

    /* Mining (for external miners) */
    ftc_block_t* (*get_block_template)(void* ctx, const ftc_address_t miner_addr);
    bool (*submit_block)(void* ctx, ftc_block_t* block);

    /* Data directory (for blocks.dat sync) */
    const char* (*get_data_dir)(void* ctx);

    /* User data */
    void* user_data;
} ftc_rpc_handlers_t;

/*==============================================================================
 * RPC SERVER
 *============================================================================*/

typedef struct {
    ftc_rpc_socket_t    listen_socket;
    uint16_t            port;
    bool                running;

    ftc_rpc_handlers_t* handlers;

    /* Connection tracking */
    ftc_rpc_socket_t    clients[FTC_RPC_MAX_CONNECTIONS];
    int                 client_count;

} ftc_rpc_server_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create RPC server
 */
ftc_rpc_server_t* ftc_rpc_new(void);

/**
 * Free RPC server
 */
void ftc_rpc_free(ftc_rpc_server_t* rpc);

/**
 * Set handlers for RPC methods
 */
void ftc_rpc_set_handlers(ftc_rpc_server_t* rpc, ftc_rpc_handlers_t* handlers);

/**
 * Start RPC server
 */
bool ftc_rpc_start(ftc_rpc_server_t* rpc, uint16_t port);

/**
 * Stop RPC server
 */
void ftc_rpc_stop(ftc_rpc_server_t* rpc);

/**
 * Process RPC requests (call periodically)
 */
void ftc_rpc_poll(ftc_rpc_server_t* rpc, int timeout_ms);

/*==============================================================================
 * JSON UTILITIES
 *============================================================================*/

/**
 * Simple JSON string builder
 */
typedef struct {
    char*   data;
    size_t  len;
    size_t  capacity;
} ftc_json_t;

ftc_json_t* ftc_json_new(void);
void ftc_json_free(ftc_json_t* json);

void ftc_json_object_start(ftc_json_t* json);
void ftc_json_object_end(ftc_json_t* json);
void ftc_json_array_start(ftc_json_t* json);
void ftc_json_array_end(ftc_json_t* json);

void ftc_json_key(ftc_json_t* json, const char* key);
void ftc_json_string(ftc_json_t* json, const char* value);
void ftc_json_int(ftc_json_t* json, int64_t value);
void ftc_json_uint(ftc_json_t* json, uint64_t value);
void ftc_json_double(ftc_json_t* json, double value);
void ftc_json_bool(ftc_json_t* json, bool value);
void ftc_json_null(ftc_json_t* json);
void ftc_json_raw(ftc_json_t* json, const char* raw);

void ftc_json_kv_string(ftc_json_t* json, const char* key, const char* value);
void ftc_json_kv_int(ftc_json_t* json, const char* key, int64_t value);
void ftc_json_kv_uint(ftc_json_t* json, const char* key, uint64_t value);
void ftc_json_kv_double(ftc_json_t* json, const char* key, double value);
void ftc_json_kv_bool(ftc_json_t* json, const char* key, bool value);
void ftc_json_kv_null(ftc_json_t* json, const char* key);

/**
 * Parse JSON value (simple implementation)
 */
const char* ftc_json_parse_string(const char* json, const char* key, char* out, size_t out_len);
bool ftc_json_parse_int(const char* json, const char* key, int64_t* out);
bool ftc_json_parse_uint(const char* json, const char* key, uint64_t* out);
bool ftc_json_parse_bool(const char* json, const char* key, bool* out);

#ifdef __cplusplus
}
#endif

#endif /* FTC_RPC_H */
