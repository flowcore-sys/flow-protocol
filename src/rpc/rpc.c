/**
 * FTC JSON-RPC Server Implementation
 */

#include "rpc.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define FTC_RPC_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define FTC_RPC_INVALID_SOCKET -1
#endif

/*==============================================================================
 * PLATFORM UTILITIES
 *============================================================================*/

static void close_rpc_socket(ftc_rpc_socket_t sock)
{
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

static bool set_rpc_nonblocking(ftc_rpc_socket_t sock)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

/*==============================================================================
 * JSON BUILDER
 *============================================================================*/

ftc_json_t* ftc_json_new(void)
{
    ftc_json_t* json = (ftc_json_t*)calloc(1, sizeof(ftc_json_t));
    if (!json) return NULL;

    json->capacity = 4096;
    json->data = (char*)malloc(json->capacity);
    if (!json->data) {
        free(json);
        return NULL;
    }
    json->data[0] = '\0';
    json->len = 0;
    return json;
}

void ftc_json_free(ftc_json_t* json)
{
    if (json) {
        free(json->data);
        free(json);
    }
}

static bool json_ensure_capacity(ftc_json_t* json, size_t needed)
{
    if (json->len + needed >= json->capacity) {
        size_t new_capacity = (json->len + needed) * 2;
        char* new_data = (char*)realloc(json->data, new_capacity);
        if (!new_data) {
            return false;  /* Allocation failed, keep old buffer */
        }
        json->data = new_data;
        json->capacity = new_capacity;
    }
    return true;
}

static void json_append(ftc_json_t* json, const char* str)
{
    size_t len = strlen(str);
    if (!json_ensure_capacity(json, len + 1)) return;
    memcpy(json->data + json->len, str, len + 1);
    json->len += len;
}

static void json_append_char(ftc_json_t* json, char c)
{
    if (!json_ensure_capacity(json, 2)) return;
    json->data[json->len++] = c;
    json->data[json->len] = '\0';
}

void ftc_json_object_start(ftc_json_t* json)
{
    json_append_char(json, '{');
}

void ftc_json_object_end(ftc_json_t* json)
{
    /* Remove trailing comma if present */
    if (json->len > 0 && json->data[json->len - 1] == ',') {
        json->len--;
        json->data[json->len] = '\0';
    }
    json_append(json, "},");
}

void ftc_json_array_start(ftc_json_t* json)
{
    json_append_char(json, '[');
}

void ftc_json_array_end(ftc_json_t* json)
{
    if (json->len > 0 && json->data[json->len - 1] == ',') {
        json->len--;
        json->data[json->len] = '\0';
    }
    json_append(json, "],");
}

static void ftc_json_finalize(ftc_json_t* json)
{
    /* Remove trailing comma from the final JSON */
    if (json->len > 0 && json->data[json->len - 1] == ',') {
        json->len--;
        json->data[json->len] = '\0';
    }
}

void ftc_json_key(ftc_json_t* json, const char* key)
{
    json_append_char(json, '"');
    json_append(json, key);
    json_append(json, "\":");
}

void ftc_json_string(ftc_json_t* json, const char* value)
{
    json_append_char(json, '"');
    /* Escape special characters */
    for (const char* p = value; *p; p++) {
        if (*p == '"') json_append(json, "\\\"");
        else if (*p == '\\') json_append(json, "\\\\");
        else if (*p == '\n') json_append(json, "\\n");
        else if (*p == '\r') json_append(json, "\\r");
        else if (*p == '\t') json_append(json, "\\t");
        else json_append_char(json, *p);
    }
    json_append(json, "\",");
}

void ftc_json_int(ftc_json_t* json, int64_t value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld,", (long long)value);
    json_append(json, buf);
}

void ftc_json_uint(ftc_json_t* json, uint64_t value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu,", (unsigned long long)value);
    json_append(json, buf);
}

void ftc_json_double(ftc_json_t* json, double value)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%.8f,", value);
    json_append(json, buf);
}

void ftc_json_bool(ftc_json_t* json, bool value)
{
    json_append(json, value ? "true," : "false,");
}

void ftc_json_null(ftc_json_t* json)
{
    json_append(json, "null,");
}

void ftc_json_raw(ftc_json_t* json, const char* raw)
{
    json_append(json, raw);
    json_append_char(json, ',');
}

void ftc_json_kv_string(ftc_json_t* json, const char* key, const char* value)
{
    ftc_json_key(json, key);
    ftc_json_string(json, value);
}

void ftc_json_kv_int(ftc_json_t* json, const char* key, int64_t value)
{
    ftc_json_key(json, key);
    ftc_json_int(json, value);
}

void ftc_json_kv_uint(ftc_json_t* json, const char* key, uint64_t value)
{
    ftc_json_key(json, key);
    ftc_json_uint(json, value);
}

void ftc_json_kv_double(ftc_json_t* json, const char* key, double value)
{
    ftc_json_key(json, key);
    ftc_json_double(json, value);
}

void ftc_json_kv_bool(ftc_json_t* json, const char* key, bool value)
{
    ftc_json_key(json, key);
    ftc_json_bool(json, value);
}

void ftc_json_kv_null(ftc_json_t* json, const char* key)
{
    ftc_json_key(json, key);
    ftc_json_null(json);
}

/*==============================================================================
 * JSON PARSING (minimal implementation)
 *============================================================================*/

static const char* find_key(const char* json, const char* key)
{
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char* p = strstr(json, pattern);
    if (!p) return NULL;

    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':')) p++;
    return p;
}

const char* ftc_json_parse_string(const char* json, const char* key, char* out, size_t out_len)
{
    const char* p = find_key(json, key);
    if (!p || *p != '"') return NULL;

    p++;  /* Skip opening quote */
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            if (*p == 'n') out[i++] = '\n';
            else if (*p == 'r') out[i++] = '\r';
            else if (*p == 't') out[i++] = '\t';
            else out[i++] = *p;
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return out;
}

bool ftc_json_parse_int(const char* json, const char* key, int64_t* out)
{
    const char* p = find_key(json, key);
    if (!p) return false;

    char* end;
    *out = strtoll(p, &end, 10);
    return end != p;
}

bool ftc_json_parse_uint(const char* json, const char* key, uint64_t* out)
{
    const char* p = find_key(json, key);
    if (!p) return false;

    char* end;
    *out = strtoull(p, &end, 10);
    return end != p;
}

bool ftc_json_parse_bool(const char* json, const char* key, bool* out)
{
    const char* p = find_key(json, key);
    if (!p) return false;

    if (strncmp(p, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

/*==============================================================================
 * RPC SERVER
 *============================================================================*/

ftc_rpc_server_t* ftc_rpc_new(void)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    ftc_rpc_server_t* rpc = (ftc_rpc_server_t*)calloc(1, sizeof(ftc_rpc_server_t));
    if (!rpc) return NULL;

    rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
    for (int i = 0; i < FTC_RPC_MAX_CONNECTIONS; i++) {
        rpc->clients[i] = FTC_RPC_INVALID_SOCKET;
    }

    return rpc;
}

void ftc_rpc_free(ftc_rpc_server_t* rpc)
{
    if (!rpc) return;
    ftc_rpc_stop(rpc);
    free(rpc);
}

void ftc_rpc_set_handlers(ftc_rpc_server_t* rpc, ftc_rpc_handlers_t* handlers)
{
    rpc->handlers = handlers;
}

bool ftc_rpc_start(ftc_rpc_server_t* rpc, uint16_t port)
{
    if (rpc->running) return true;

    rpc->listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (rpc->listen_socket == FTC_RPC_INVALID_SOCKET) {
        return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(rpc->listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(rpc->listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(rpc->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
        return false;
    }

    if (listen(rpc->listen_socket, 10) != 0) {
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
        return false;
    }

    set_rpc_nonblocking(rpc->listen_socket);
    rpc->port = port;
    rpc->running = true;

    printf("[RPC] Listening on port %d\n", port);
    return true;
}

void ftc_rpc_stop(ftc_rpc_server_t* rpc)
{
    rpc->running = false;

    if (rpc->listen_socket != FTC_RPC_INVALID_SOCKET) {
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
    }

    for (int i = 0; i < FTC_RPC_MAX_CONNECTIONS; i++) {
        if (rpc->clients[i] != FTC_RPC_INVALID_SOCKET) {
            close_rpc_socket(rpc->clients[i]);
            rpc->clients[i] = FTC_RPC_INVALID_SOCKET;
        }
    }
    rpc->client_count = 0;
}

/*==============================================================================
 * RPC METHOD HANDLERS
 *============================================================================*/

static void rpc_error(ftc_json_t* json, int code, const char* message, const char* id)
{
    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "error");
    ftc_json_object_start(json);
    ftc_json_kv_int(json, "code", code);
    ftc_json_kv_string(json, "message", message);
    ftc_json_object_end(json);

    if (id) {
        ftc_json_kv_string(json, "id", id);
    } else {
        ftc_json_kv_null(json, "id");
    }
    ftc_json_object_end(json);
}

static void rpc_getblockcount(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    uint32_t height = 0;
    if (rpc->handlers && rpc->handlers->get_best_height) {
        height = rpc->handlers->get_best_height(rpc->handlers->user_data);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_uint(json, "result", height);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getbestblockhash(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    ftc_hash256_t hash = {0};
    if (rpc->handlers && rpc->handlers->get_best_hash) {
        rpc->handlers->get_best_hash(rpc->handlers->user_data, hash);
    }

    char hex[65];
    ftc_hash_to_hex(hash, hex);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_string(json, "result", hex);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getdifficulty(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    double diff = 1.0;
    if (rpc->handlers && rpc->handlers->get_difficulty) {
        diff = rpc->handlers->get_difficulty(rpc->handlers->user_data);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_double(json, "result", diff);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getpeercount(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    int count = 0;
    if (rpc->handlers && rpc->handlers->get_peer_count) {
        count = rpc->handlers->get_peer_count(rpc->handlers->user_data);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_int(json, "result", count);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getconnectioncount(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    int count = 0;
    if (rpc->handlers && rpc->handlers->get_connection_count) {
        count = rpc->handlers->get_connection_count(rpc->handlers->user_data);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_int(json, "result", count);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getbalance(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse address from params */
    char addr_str[128] = {0};

    /* Try to find address in params array */
    const char* p = strchr(params, '"');
    if (p) {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(addr_str) - 1) {
            addr_str[i++] = *p++;
        }
        addr_str[i] = '\0';
    }

    uint64_t balance = 0;

    if (addr_str[0] && rpc->handlers && rpc->handlers->get_balance) {
        ftc_address_t addr;
        if (ftc_address_decode(addr_str, addr, NULL)) {
            rpc->handlers->get_balance(rpc->handlers->user_data, addr, &balance);
        }
    }

    /* Convert to FTC with decimals */
    double ftc_balance = (double)balance / FTC_COIN;

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_double(json, "result", ftc_balance);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getblock(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse hash or height from params */
    char hash_str[128] = {0};

    const char* p = strchr(params, '"');
    if (p) {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(hash_str) - 1) {
            hash_str[i++] = *p++;
        }
        hash_str[i] = '\0';
    }

    ftc_block_t* block = NULL;

    if (hash_str[0] && rpc->handlers) {
        if (strlen(hash_str) == 64 && rpc->handlers->get_block_by_hash) {
            ftc_hash256_t hash;
            ftc_hex_to_hash(hash_str, hash);
            block = rpc->handlers->get_block_by_hash(rpc->handlers->user_data, hash);
        } else if (rpc->handlers->get_block_by_height) {
            uint32_t height = (uint32_t)atoi(hash_str);
            block = rpc->handlers->get_block_by_height(rpc->handlers->user_data, height);
        }
    }

    if (!block) {
        rpc_error(json, -5, "Block not found", id);
        return;
    }

    /* Build block JSON */
    ftc_hash256_t block_hash;
    ftc_block_hash(block, block_hash);
    char hex[65];
    ftc_hash_to_hex(block_hash, hex);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);

    ftc_json_kv_string(json, "hash", hex);
    ftc_json_kv_int(json, "version", block->header.version);

    ftc_hash_to_hex(block->header.prev_hash, hex);
    ftc_json_kv_string(json, "previousblockhash", hex);

    ftc_hash_to_hex(block->header.merkle_root, hex);
    ftc_json_kv_string(json, "merkleroot", hex);

    ftc_json_kv_uint(json, "time", block->header.timestamp);

    char bits_hex[16];
    snprintf(bits_hex, sizeof(bits_hex), "%08x", block->header.bits);
    ftc_json_kv_string(json, "bits", bits_hex);

    ftc_json_kv_uint(json, "nonce", block->header.nonce);
    ftc_json_kv_uint(json, "tx_count", block->tx_count);

    double diff = ftc_bits_to_difficulty(block->header.bits);
    ftc_json_kv_double(json, "difficulty", diff);

    /* Transaction hashes */
    ftc_json_key(json, "tx");
    ftc_json_array_start(json);
    for (uint32_t i = 0; i < block->tx_count; i++) {
        ftc_tx_hash(block->txs[i], block_hash);
        ftc_hash_to_hex(block_hash, hex);
        ftc_json_string(json, hex);
    }
    ftc_json_array_end(json);

    ftc_json_object_end(json);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    ftc_block_free(block);
}

static void rpc_gettransaction(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    char txid_str[128] = {0};

    const char* p = strchr(params, '"');
    if (p) {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(txid_str) - 1) {
            txid_str[i++] = *p++;
        }
        txid_str[i] = '\0';
    }

    ftc_tx_t* tx = NULL;

    if (txid_str[0] && rpc->handlers && rpc->handlers->get_tx) {
        ftc_hash256_t txid;
        ftc_hex_to_hash(txid_str, txid);
        tx = rpc->handlers->get_tx(rpc->handlers->user_data, txid);
    }

    if (!tx) {
        rpc_error(json, -5, "Transaction not found", id);
        return;
    }

    ftc_hash256_t txid;
    ftc_tx_hash(tx, txid);
    char hex[65];
    ftc_hash_to_hex(txid, hex);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);

    ftc_json_kv_string(json, "txid", hex);
    ftc_json_kv_int(json, "version", tx->version);
    ftc_json_kv_uint(json, "locktime", tx->locktime);

    /* Inputs */
    ftc_json_key(json, "vin");
    ftc_json_array_start(json);
    for (uint32_t i = 0; i < tx->input_count; i++) {
        ftc_json_object_start(json);
        ftc_hash_to_hex(tx->inputs[i].prev_txid, hex);
        ftc_json_kv_string(json, "txid", hex);
        ftc_json_kv_uint(json, "vout", tx->inputs[i].prev_index);
        ftc_json_object_end(json);
    }
    ftc_json_array_end(json);

    /* Outputs */
    ftc_json_key(json, "vout");
    ftc_json_array_start(json);
    for (uint32_t i = 0; i < tx->output_count; i++) {
        ftc_json_object_start(json);
        ftc_json_kv_double(json, "value", (double)tx->outputs[i].value / FTC_COIN);
        ftc_json_kv_uint(json, "n", i);

        char addr_str[64];
        ftc_address_encode(tx->outputs[i].pubkey_hash, true, addr_str);
        ftc_json_kv_string(json, "address", addr_str);

        ftc_json_object_end(json);
    }
    ftc_json_array_end(json);

    ftc_json_object_end(json);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    ftc_tx_free(tx);
}

static void rpc_sendrawtransaction(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Find hex string in params */
    const char* p = strchr(params, '"');
    if (!p) {
        rpc_error(json, -1, "Missing transaction hex", id);
        return;
    }
    p++;

    const char* end = strchr(p, '"');
    if (!end) {
        rpc_error(json, -1, "Invalid transaction hex format", id);
        return;
    }

    size_t hex_len = end - p;
    if (hex_len == 0 || hex_len > 65536) {
        rpc_error(json, -1, "Invalid transaction hex length", id);
        return;
    }

    char* hex_str = (char*)malloc(hex_len + 1);
    if (!hex_str) {
        rpc_error(json, -1, "Memory allocation failed", id);
        return;
    }
    memcpy(hex_str, p, hex_len);
    hex_str[hex_len] = '\0';

    ftc_tx_t* tx = ftc_tx_from_hex(hex_str);
    free(hex_str);
    if (!tx) {
        rpc_error(json, -22, "Invalid transaction", id);
        return;
    }

    bool success = false;
    if (rpc->handlers && rpc->handlers->send_tx) {
        success = rpc->handlers->send_tx(rpc->handlers->user_data, tx);
    }

    if (!success) {
        ftc_tx_free(tx);
        rpc_error(json, -25, "Transaction rejected", id);
        return;
    }

    ftc_hash256_t txid;
    ftc_tx_hash(tx, txid);
    char hex[65];
    ftc_hash_to_hex(txid, hex);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_string(json, "result", hex);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    ftc_tx_free(tx);
}

static void rpc_sendtoaddress(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse params: ["privkey_hex", "to_address", amount, fee (optional)] */
    char privkey_hex[128] = {0};
    char to_addr_str[64] = {0};
    double amount_ftc = 0;
    double fee_ftc = 0.0001;  /* Default fee: 0.0001 FTC */

    /* Parse private key hex */
    const char* p = strchr(params, '"');
    if (!p) {
        rpc_error(json, -1, "Missing private key", id);
        return;
    }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < sizeof(privkey_hex) - 1) {
        privkey_hex[i++] = *p++;
    }
    privkey_hex[i] = '\0';

    if (strlen(privkey_hex) != 64) {
        rpc_error(json, -1, "Invalid private key (must be 64 hex chars)", id);
        return;
    }

    /* Parse to address */
    p = strchr(p + 1, '"');
    if (!p) {
        rpc_error(json, -1, "Missing destination address", id);
        return;
    }
    p++;
    i = 0;
    while (*p && *p != '"' && i < sizeof(to_addr_str) - 1) {
        to_addr_str[i++] = *p++;
    }
    to_addr_str[i] = '\0';

    /* Parse amount */
    p = strchr(p + 1, ',');
    if (!p) {
        rpc_error(json, -1, "Missing amount", id);
        return;
    }
    p++;
    while (*p == ' ') p++;
    amount_ftc = strtod(p, NULL);
    if (amount_ftc <= 0) {
        rpc_error(json, -1, "Invalid amount", id);
        return;
    }

    /* Parse optional fee */
    p = strchr(p, ',');
    if (p) {
        p++;
        while (*p == ' ') p++;
        double parsed_fee = strtod(p, NULL);
        if (parsed_fee > 0) {
            fee_ftc = parsed_fee;
        }
    }

    /* Convert amounts to satoshis */
    uint64_t amount = (uint64_t)(amount_ftc * FTC_COIN);
    uint64_t fee = (uint64_t)(fee_ftc * FTC_COIN);

    /* Decode private key from hex */
    ftc_privkey_t privkey;
    for (int j = 0; j < 32; j++) {
        unsigned int byte;
        sscanf(privkey_hex + j * 2, "%02x", &byte);
        privkey[j] = (uint8_t)byte;
    }

    /* Derive public key and address */
    ftc_pubkey_t pubkey;
    ftc_address_t from_addr;
    ftc_pubkey_from_privkey(privkey, pubkey);
    ftc_address_from_pubkey(pubkey, from_addr);

    /* Decode destination address */
    ftc_address_t to_addr;
    if (!ftc_address_decode(to_addr_str, to_addr, NULL)) {
        rpc_error(json, -1, "Invalid destination address", id);
        memset(privkey, 0, 32);
        return;
    }

    /* Get UTXOs for sender */
    if (!rpc->handlers || !rpc->handlers->get_utxos) {
        rpc_error(json, -1, "get_utxos handler not available", id);
        memset(privkey, 0, 32);
        return;
    }

    ftc_utxo_t* utxos = NULL;
    size_t utxo_count = 0;
    if (!rpc->handlers->get_utxos(rpc->handlers->user_data, from_addr, &utxos, &utxo_count)) {
        rpc_error(json, -1, "Failed to get UTXOs", id);
        memset(privkey, 0, 32);
        return;
    }

    if (utxo_count == 0) {
        rpc_error(json, -6, "Insufficient funds (no UTXOs)", id);
        memset(privkey, 0, 32);
        return;
    }

    /* Select UTXOs (simple: use all needed) */
    uint64_t total_input = 0;
    size_t selected_count = 0;
    for (size_t k = 0; k < utxo_count && total_input < amount + fee; k++) {
        total_input += utxos[k].value;
        selected_count++;
    }

    if (total_input < amount + fee) {
        rpc_error(json, -6, "Insufficient funds", id);
        free(utxos);
        memset(privkey, 0, 32);
        return;
    }

    /* Create transaction */
    ftc_tx_t* tx = ftc_tx_new();
    if (!tx) {
        rpc_error(json, -1, "Failed to create transaction", id);
        free(utxos);
        memset(privkey, 0, 32);
        return;
    }

    /* Add inputs */
    for (size_t k = 0; k < selected_count; k++) {
        ftc_tx_add_input(tx, utxos[k].txid, utxos[k].vout);
    }

    /* Add output to recipient */
    ftc_tx_add_output(tx, amount, to_addr);

    /* Add change output if needed */
    uint64_t change = total_input - amount - fee;
    if (change > 0) {
        ftc_tx_add_output(tx, change, from_addr);
    }

    /* Sign all inputs */
    for (uint32_t k = 0; k < tx->input_count; k++) {
        if (!ftc_tx_sign_input(tx, k, privkey, pubkey)) {
            rpc_error(json, -1, "Failed to sign transaction", id);
            ftc_tx_free(tx);
            free(utxos);
            memset(privkey, 0, 32);
            return;
        }
    }

    /* Clear private key */
    memset(privkey, 0, 32);
    free(utxos);

    /* Broadcast transaction */
    if (!rpc->handlers || !rpc->handlers->send_tx) {
        rpc_error(json, -1, "send_tx handler not available", id);
        ftc_tx_free(tx);
        return;
    }

    /* Calculate txid before sending (send_tx takes ownership) */
    ftc_hash256_t txid;
    ftc_tx_hash(tx, txid);
    char hex[65];
    ftc_hash_to_hex(txid, hex);

    if (!rpc->handlers->send_tx(rpc->handlers->user_data, tx)) {
        ftc_tx_free(tx);
        rpc_error(json, -25, "Transaction rejected", id);
        return;
    }

    /* tx is now owned by mempool - DO NOT free it here */

    /* Return txid */
    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_string(json, "result", hex);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_listunspent(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse address from params */
    char addr_str[128] = {0};

    const char* p = strchr(params, '"');
    if (p) {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(addr_str) - 1) {
            addr_str[i++] = *p++;
        }
        addr_str[i] = '\0';
    }

    if (!addr_str[0]) {
        rpc_error(json, -1, "Missing address", id);
        return;
    }

    ftc_address_t addr;
    if (!ftc_address_decode(addr_str, addr, NULL)) {
        rpc_error(json, -1, "Invalid address", id);
        return;
    }

    if (!rpc->handlers || !rpc->handlers->get_utxos) {
        rpc_error(json, -1, "get_utxos handler not available", id);
        return;
    }

    ftc_utxo_t* utxos = NULL;
    size_t utxo_count = 0;
    if (!rpc->handlers->get_utxos(rpc->handlers->user_data, addr, &utxos, &utxo_count)) {
        rpc_error(json, -1, "Failed to get UTXOs", id);
        return;
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_array_start(json);

    for (size_t i = 0; i < utxo_count; i++) {
        ftc_json_object_start(json);

        char txid_hex[65];
        ftc_hash_to_hex(utxos[i].txid, txid_hex);
        ftc_json_kv_string(json, "txid", txid_hex);
        ftc_json_kv_uint(json, "vout", utxos[i].vout);
        ftc_json_kv_double(json, "amount", (double)utxos[i].value / FTC_COIN);
        ftc_json_kv_uint(json, "confirmations", utxos[i].height);

        ftc_json_object_end(json);
    }

    ftc_json_array_end(json);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    free(utxos);
}

static void rpc_getinfo(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    uint32_t height = 0;
    double diff = 1.0;
    int peers = 0;

    if (rpc->handlers) {
        if (rpc->handlers->get_best_height)
            height = rpc->handlers->get_best_height(rpc->handlers->user_data);
        if (rpc->handlers->get_difficulty)
            diff = rpc->handlers->get_difficulty(rpc->handlers->user_data);
        if (rpc->handlers->get_peer_count)
            peers = rpc->handlers->get_peer_count(rpc->handlers->user_data);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_string(json, "chain", "ftc");
    ftc_json_kv_uint(json, "blocks", height);
    ftc_json_kv_double(json, "difficulty", diff);
    ftc_json_kv_int(json, "connections", peers);
    ftc_json_kv_string(json, "version", FTC_USER_AGENT);
    ftc_json_kv_int(json, "protocolversion", FTC_PROTOCOL_VERSION);
    ftc_json_object_end(json);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getblocktemplate(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse miner address from params */
    char addr_str[64] = {0};

    const char* p = strchr(params, '"');
    if (p) {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(addr_str) - 1) {
            addr_str[i++] = *p++;
        }
        addr_str[i] = '\0';
    }

    if (!addr_str[0]) {
        rpc_error(json, -1, "Missing miner address", id);
        return;
    }

    ftc_address_t miner_addr;
    if (!ftc_address_decode(addr_str, miner_addr, NULL)) {
        rpc_error(json, -1, "Invalid miner address", id);
        return;
    }

    if (!rpc->handlers || !rpc->handlers->get_block_template) {
        rpc_error(json, -1, "getblocktemplate handler not available", id);
        return;
    }

    ftc_block_t* block = rpc->handlers->get_block_template(rpc->handlers->user_data, miner_addr);
    if (!block) {
        rpc_error(json, -1, "Failed to create block template", id);
        return;
    }

    /* Serialize block to hex */
    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) {
        ftc_block_free(block);
        rpc_error(json, -1, "Memory allocation failed", id);
        return;
    }
    ftc_block_serialize(block, data, size);

    char* hex = (char*)malloc(size * 2 + 1);
    if (!hex) {
        free(data);
        ftc_block_free(block);
        rpc_error(json, -1, "Memory allocation failed", id);
        return;
    }
    for (size_t i = 0; i < size; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    free(data);

    uint32_t height = 0;
    if (rpc->handlers->get_best_height)
        height = rpc->handlers->get_best_height(rpc->handlers->user_data) + 1;

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_uint(json, "height", height);
    ftc_json_kv_uint(json, "bits", block->header.bits);

    double diff = 1.0;
    if (rpc->handlers->get_difficulty)
        diff = rpc->handlers->get_difficulty(rpc->handlers->user_data);
    ftc_json_kv_double(json, "difficulty", diff);

    ftc_json_kv_string(json, "blockdata", hex);
    ftc_json_object_end(json);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    free(hex);
    ftc_block_free(block);
}

static void rpc_submitblock(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse block hex from params */
    const char* p = strchr(params, '"');
    if (!p) {
        rpc_error(json, -1, "Missing block data", id);
        return;
    }
    p++;

    /* Find end of hex string */
    const char* end = strchr(p, '"');
    if (!end) {
        rpc_error(json, -1, "Invalid block data format", id);
        return;
    }

    size_t hex_len = end - p;
    if (hex_len % 2 != 0 || hex_len < 160) {  /* Minimum block size */
        rpc_error(json, -1, "Invalid block data length", id);
        return;
    }

    /* Convert hex to binary */
    size_t data_len = hex_len / 2;
    uint8_t* data = (uint8_t*)malloc(data_len);
    if (!data) {
        rpc_error(json, -1, "Memory allocation failed", id);
        return;
    }

    for (size_t i = 0; i < data_len; i++) {
        unsigned int byte;
        sscanf(p + i * 2, "%02x", &byte);
        data[i] = (uint8_t)byte;
    }

    /* Deserialize block */
    ftc_block_t* block = ftc_block_deserialize(data, data_len);
    free(data);

    if (!block) {
        rpc_error(json, -1, "Failed to deserialize block", id);
        return;
    }

    /* Submit block */
    if (!rpc->handlers || !rpc->handlers->submit_block) {
        rpc_error(json, -1, "submitblock handler not available", id);
        ftc_block_free(block);
        return;
    }

    bool success = rpc->handlers->submit_block(rpc->handlers->user_data, block);
    ftc_block_free(block);

    if (!success) {
        rpc_error(json, -1, "Block rejected", id);
        return;
    }

    /* Success - return null (Bitcoin-style) */
    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_null(json, "result");
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

/*==============================================================================
 * REQUEST HANDLING
 *============================================================================*/

static void process_request(ftc_rpc_server_t* rpc, const char* request, ftc_json_t* response)
{
    /* Parse method and id */
    char method[64] = {0};
    char id[64] = {0};

    ftc_json_parse_string(request, "method", method, sizeof(method));
    ftc_json_parse_string(request, "id", id, sizeof(id));

    if (!method[0]) {
        rpc_error(response, -32600, "Invalid Request", id[0] ? id : NULL);
        return;
    }

    /* Find params */
    const char* params = strstr(request, "\"params\"");
    if (params) {
        params = strchr(params, ':');
        if (params) params++;
    }

    /* Dispatch to method handler */
    if (strcmp(method, "getblockcount") == 0) {
        rpc_getblockcount(rpc, response, id);
    } else if (strcmp(method, "getbestblockhash") == 0) {
        rpc_getbestblockhash(rpc, response, id);
    } else if (strcmp(method, "getdifficulty") == 0) {
        rpc_getdifficulty(rpc, response, id);
    } else if (strcmp(method, "getpeercount") == 0 || strcmp(method, "getconnectioncount") == 0) {
        rpc_getpeercount(rpc, response, id);
    } else if (strcmp(method, "getbalance") == 0) {
        rpc_getbalance(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "getblock") == 0) {
        rpc_getblock(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "gettransaction") == 0 || strcmp(method, "getrawtransaction") == 0) {
        rpc_gettransaction(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "sendrawtransaction") == 0) {
        rpc_sendrawtransaction(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "sendtoaddress") == 0) {
        rpc_sendtoaddress(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "listunspent") == 0) {
        rpc_listunspent(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "getinfo") == 0) {
        rpc_getinfo(rpc, response, id);
    } else if (strcmp(method, "getblocktemplate") == 0) {
        rpc_getblocktemplate(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "submitblock") == 0) {
        rpc_submitblock(rpc, response, params ? params : "[]", id);
    } else {
        rpc_error(response, -32601, "Method not found", id);
    }
}

static void handle_client(ftc_rpc_server_t* rpc, ftc_rpc_socket_t client)
{
    /* Set receive timeout to prevent blocking */
#ifdef _WIN32
    DWORD timeout = 3000;  /* 3 seconds */
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    /* Use smaller buffer and dynamic allocation to avoid stack overflow */
    size_t request_capacity = 65536;  /* Start with 64KB */
    char* request = (char*)malloc(request_capacity);
    if (!request) {
        close_rpc_socket(client);
        return;
    }

    int total = 0;

    /* Receive HTTP request */
    while (total < (int)request_capacity - 1) {
        int ret = recv(client, request + total, (int)(request_capacity - 1 - total), 0);
        if (ret <= 0) break;
        total += ret;

        /* Check for end of HTTP headers */
        if (strstr(request, "\r\n\r\n")) break;
    }
    request[total] = '\0';

    /* Find JSON body (after headers) */
    char* body = strstr(request, "\r\n\r\n");
    if (!body) {
        free(request);
        close_rpc_socket(client);
        return;
    }
    body += 4;

    /* Parse Content-Length if we need more data */
    char* cl = strstr(request, "Content-Length:");
    if (cl) {
        int content_len = atoi(cl + 15);
        int body_len = total - (int)(body - request);

        /* Expand buffer if needed */
        size_t needed = (body - request) + content_len + 1;
        if (needed > request_capacity && needed <= FTC_RPC_MAX_REQUEST) {
            size_t body_offset = body - request;  /* Save offset before realloc */
            char* new_buf = (char*)realloc(request, needed);
            if (new_buf) {
                request = new_buf;
                body = request + body_offset;  /* Restore body pointer */
                request_capacity = needed;
            } else {
                /* Realloc failed, continue with what we have */
            }
        }

        while (body_len < content_len && total < (int)request_capacity - 1) {
            int ret = recv(client, request + total, (int)(request_capacity - 1 - total), 0);
            if (ret <= 0) break;
            total += ret;
            body_len += ret;
        }
        request[total] = '\0';
    }

    /* Process JSON-RPC request */
    ftc_json_t* response = ftc_json_new();
    process_request(rpc, body, response);
    ftc_json_finalize(response);

    /* Send HTTP response */
    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n",
             response->len);

    send(client, header, (int)strlen(header), 0);
    send(client, response->data, (int)response->len, 0);

    ftc_json_free(response);
    free(request);
    close_rpc_socket(client);
}

void ftc_rpc_poll(ftc_rpc_server_t* rpc, int timeout_ms)
{
    if (!rpc->running) return;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(rpc->listen_socket, &read_fds);

    ftc_rpc_socket_t max_fd = rpc->listen_socket;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select((int)(max_fd + 1), &read_fds, NULL, NULL, &tv);
    if (ret <= 0) return;

    if (FD_ISSET(rpc->listen_socket, &read_fds)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ftc_rpc_socket_t client = accept(rpc->listen_socket, (struct sockaddr*)&addr, &addr_len);

        if (client != FTC_RPC_INVALID_SOCKET) {
            handle_client(rpc, client);
        }
    }
}
