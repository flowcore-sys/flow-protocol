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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define FTC_RPC_INVALID_SOCKET -1
#endif

/* Cross-platform unused attribute */
#ifdef _MSC_VER
#define MAYBE_UNUSED
#else
#define MAYBE_UNUSED __attribute__((unused))
#endif

/*==============================================================================
 * PLATFORM UTILITIES
 *============================================================================*/

static void close_rpc_socket(ftc_rpc_socket_t sock)
{
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
    closesocket(sock);
#else
    shutdown(sock, SHUT_RDWR);
    close(sock);
#endif
}

/* Configure client socket for optimal performance and reduced TIME_WAIT */
static void configure_client_socket(ftc_rpc_socket_t sock)
{
    int opt = 1;

    /* Disable Nagle's algorithm for lower latency */
#ifdef _WIN32
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
#else
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#endif

    /* Set SO_LINGER to avoid TIME_WAIT accumulation
     * l_onoff=1, l_linger=0 means send RST on close (no TIME_WAIT) */
    struct linger ling;
    ling.l_onoff = 1;
    ling.l_linger = 0;
#ifdef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling));
#else
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
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

/* Extract nth quoted string from params array (0-indexed) */
static const char* extract_param_string(const char* params, int n, char* out, size_t out_len)
{
    const char* p = params;
    for (int i = 0; i <= n; i++) {
        p = strchr(p, '"');
        if (!p) return NULL;
        if (i < n) { p++; p = strchr(p, '"'); if (p) p++; }
    }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return out;
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

    /* Allocate dynamic client array */
    rpc->client_capacity = FTC_RPC_INITIAL_CONNECTIONS;
    rpc->clients = (ftc_rpc_socket_t*)malloc(rpc->client_capacity * sizeof(ftc_rpc_socket_t));
    if (!rpc->clients) {
        free(rpc);
        return NULL;
    }
    for (int i = 0; i < rpc->client_capacity; i++) {
        rpc->clients[i] = FTC_RPC_INVALID_SOCKET;
    }

    /* Allocate dynamic miner array */
    rpc->miner_capacity = FTC_INITIAL_MINERS;
    rpc->miners = (ftc_miner_info_t*)calloc(rpc->miner_capacity, sizeof(ftc_miner_info_t));
    if (!rpc->miners) {
        free(rpc->clients);
        free(rpc);
        return NULL;
    }

    /* Initialize miner tracking mutex */
    FTC_RPC_MUTEX_INIT(rpc->miner_mutex);

    return rpc;
}

/* Grow client array when needed */
MAYBE_UNUSED
static bool rpc_grow_clients(ftc_rpc_server_t* rpc)
{
    int new_capacity = rpc->client_capacity * 2;
    ftc_rpc_socket_t* new_clients = (ftc_rpc_socket_t*)realloc(rpc->clients,
                                                                new_capacity * sizeof(ftc_rpc_socket_t));
    if (!new_clients) return false;

    /* Initialize new slots */
    for (int i = rpc->client_capacity; i < new_capacity; i++) {
        new_clients[i] = FTC_RPC_INVALID_SOCKET;
    }

    rpc->clients = new_clients;
    rpc->client_capacity = new_capacity;
    return true;
}

/* Grow miner array when needed */
static bool rpc_grow_miners(ftc_rpc_server_t* rpc)
{
    int new_capacity = rpc->miner_capacity * 2;
    ftc_miner_info_t* new_miners = (ftc_miner_info_t*)realloc(rpc->miners,
                                                              new_capacity * sizeof(ftc_miner_info_t));
    if (!new_miners) return false;

    /* Zero new slots */
    memset(&new_miners[rpc->miner_capacity], 0,
           (new_capacity - rpc->miner_capacity) * sizeof(ftc_miner_info_t));

    rpc->miners = new_miners;
    rpc->miner_capacity = new_capacity;
    return true;
}

void ftc_rpc_free(ftc_rpc_server_t* rpc)
{
    if (!rpc) return;
    ftc_rpc_stop(rpc);
    FTC_RPC_MUTEX_DESTROY(rpc->miner_mutex);
    free(rpc->clients);
    free(rpc->miners);
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
#ifdef _WIN32
        printf("[RPC] socket() failed: %d\n", WSAGetLastError());
#endif
        return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(rpc->listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(rpc->listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    /* Allow binding even if TIME_WAIT sockets exist from previous instance */
#ifdef SO_REUSEPORT
    setsockopt(rpc->listen_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(rpc->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        printf("[RPC] bind() failed: %d\n", WSAGetLastError());
#endif
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
        return false;
    }

    if (listen(rpc->listen_socket, 1024) != 0) {
#ifdef _WIN32
        printf("[RPC] listen() failed: %d\n", WSAGetLastError());
#endif
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
        return false;
    }

    set_rpc_nonblocking(rpc->listen_socket);
    rpc->port = port;
    rpc->running = true;

    return true;
}

void ftc_rpc_stop(ftc_rpc_server_t* rpc)
{
    rpc->running = false;

    if (rpc->listen_socket != FTC_RPC_INVALID_SOCKET) {
        close_rpc_socket(rpc->listen_socket);
        rpc->listen_socket = FTC_RPC_INVALID_SOCKET;
    }

    for (int i = 0; i < rpc->client_capacity; i++) {
        if (rpc->clients[i] != FTC_RPC_INVALID_SOCKET) {
            close_rpc_socket(rpc->clients[i]);
            rpc->clients[i] = FTC_RPC_INVALID_SOCKET;
        }
    }
    rpc->client_count = 0;
}

/*==============================================================================
 * MINER TRACKING
 *============================================================================*/

void ftc_rpc_track_miner(ftc_rpc_server_t* rpc, const char* ip)
{
    if (!rpc || !ip || !ip[0]) return;

    int64_t now = (int64_t)time(NULL);

    FTC_RPC_MUTEX_LOCK(rpc->miner_mutex);

    /* Find existing miner */
    for (int i = 0; i < rpc->miner_count; i++) {
        if (strcmp(rpc->miners[i].ip, ip) == 0) {
            rpc->miners[i].last_seen = now;
            rpc->miners[i].requests++;
            FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
            return;
        }
    }

    /* Add new miner - grow array if needed */
    if (rpc->miner_count >= rpc->miner_capacity) {
        if (!rpc_grow_miners(rpc)) {
            FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
            return;  /* Can't grow, skip this miner */
        }
    }
    ftc_miner_info_t* miner = &rpc->miners[rpc->miner_count++];
    strncpy(miner->ip, ip, sizeof(miner->ip) - 1);
    miner->ip[sizeof(miner->ip) - 1] = '\0';
    miner->first_seen = now;
    miner->last_seen = now;
    miner->requests = 1;
    miner->blocks_found = 0;
    miner->blocks_rejected = 0;

    FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
}

void ftc_rpc_record_block(ftc_rpc_server_t* rpc, const char* ip, bool accepted)
{
    if (!rpc || !ip || !ip[0]) return;

    int64_t now = (int64_t)time(NULL);

    FTC_RPC_MUTEX_LOCK(rpc->miner_mutex);

    /* Find existing miner */
    for (int i = 0; i < rpc->miner_count; i++) {
        if (strcmp(rpc->miners[i].ip, ip) == 0) {
            if (accepted) {
                rpc->miners[i].blocks_found++;
            } else {
                rpc->miners[i].blocks_rejected++;
            }
            rpc->miners[i].last_seen = now;
            FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
            return;
        }
    }

    /* Miner not found - add new miner, grow array if needed */
    if (rpc->miner_count >= rpc->miner_capacity) {
        if (!rpc_grow_miners(rpc)) {
            FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
            return;  /* Can't grow, skip */
        }
    }
    ftc_miner_info_t* miner = &rpc->miners[rpc->miner_count++];
    strncpy(miner->ip, ip, sizeof(miner->ip) - 1);
    miner->ip[sizeof(miner->ip) - 1] = '\0';
    miner->first_seen = now;
    miner->last_seen = now;
    miner->requests = 0;
    miner->blocks_found = accepted ? 1 : 0;
    miner->blocks_rejected = accepted ? 0 : 1;

    FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);
}

int ftc_rpc_get_active_miners(ftc_rpc_server_t* rpc)
{
    if (!rpc) return 0;

    int64_t now = (int64_t)time(NULL);
    int active = 0;

    FTC_RPC_MUTEX_LOCK(rpc->miner_mutex);

    for (int i = 0; i < rpc->miner_count; i++) {
        if (now - rpc->miners[i].last_seen <= FTC_MINER_TIMEOUT) {
            active++;
        }
    }

    FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);

    return active;
}

const ftc_miner_info_t* ftc_rpc_get_miners(ftc_rpc_server_t* rpc, int* count)
{
    if (!rpc) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = rpc->miner_count;
    return rpc->miners;
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

MAYBE_UNUSED
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

static void rpc_getpeerinfo(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    /* Get peer info from handler */
    #define MAX_PEER_INFO 128
    char* addresses[MAX_PEER_INFO];
    int ports[MAX_PEER_INFO];
    int64_t ping_times[MAX_PEER_INFO];
    int count = 0;

    /* Allocate address strings */
    for (int i = 0; i < MAX_PEER_INFO; i++) {
        addresses[i] = (char*)malloc(64);
        if (!addresses[i]) {
            /* Cleanup on failure */
            for (int j = 0; j < i; j++) free(addresses[j]);
            rpc_error(json, -32603, "Memory allocation failed", id);
            return;
        }
    }

    if (rpc->handlers && rpc->handlers->get_peer_info) {
        count = rpc->handlers->get_peer_info(rpc->handlers->user_data,
                                             addresses, ports, ping_times, MAX_PEER_INFO);
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_key(json, "result");
    ftc_json_array_start(json);

    for (int i = 0; i < count; i++) {
        ftc_json_object_start(json);
        ftc_json_kv_string(json, "addr", addresses[i]);
        ftc_json_kv_int(json, "port", ports[i]);
        ftc_json_kv_int(json, "pingtime", ping_times[i]);
        ftc_json_object_end(json);
    }

    ftc_json_array_end(json);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    /* Cleanup */
    for (int i = 0; i < MAX_PEER_INFO; i++) {
        free(addresses[i]);
    }
    #undef MAX_PEER_INFO
}

static void rpc_getbalance(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    /* Parse address from params */
    char addr_str[128] = {0};
    extract_param_string(params, 0, addr_str, sizeof(addr_str));

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
    extract_param_string(params, 0, hash_str, sizeof(hash_str));

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
    extract_param_string(params, 0, txid_str, sizeof(txid_str));

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
    /* Parse params: ["privkey_hex", "pubkey_hex", "to_address", amount, fee (optional)] */
    /* pubkey_hex can be provided to use legacy keys instead of deriving from privkey */
    char privkey_hex[128] = {0};
    char pubkey_hex[128] = {0};
    char to_addr_str[64] = {0};
    double amount_ftc = 0;
    double fee_ftc = 0.0001;

    /* Parse string params */
    if (!extract_param_string(params, 0, privkey_hex, sizeof(privkey_hex)) || strlen(privkey_hex) != 64) {
        rpc_error(json, -1, "Invalid private key (must be 64 hex chars)", id);
        return;
    }
    if (!extract_param_string(params, 1, pubkey_hex, sizeof(pubkey_hex)) || strlen(pubkey_hex) != 64) {
        rpc_error(json, -1, "Invalid public key (must be 64 hex chars)", id);
        return;
    }
    if (!extract_param_string(params, 2, to_addr_str, sizeof(to_addr_str))) {
        rpc_error(json, -1, "Missing destination address", id);
        return;
    }

    /* Parse amount (4th param after 3 strings) */
    const char* p = params;
    for (int i = 0; i < 3; i++) { p = strchr(p, '"'); if (p) p = strchr(p + 1, '"'); if (p) p++; }
    p = strchr(p, ',');
    if (!p || (amount_ftc = strtod(p + 1, NULL)) <= 0) {
        rpc_error(json, -1, "Invalid amount", id);
        return;
    }

    /* Parse optional fee */
    p = strchr(p + 1, ',');
    if (p) { double f = strtod(p + 1, NULL); if (f > 0) fee_ftc = f; }

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

    /* Use provided public key directly (for legacy key support) */
    ftc_pubkey_t pubkey;
    ftc_address_t from_addr;
    for (int j = 0; j < 32; j++) {
        unsigned int byte;
        sscanf(pubkey_hex + j * 2, "%02x", &byte);
        pubkey[j] = (uint8_t)byte;
    }
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
    extract_param_string(params, 0, addr_str, sizeof(addr_str));

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

static void rpc_getblocktemplate(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id, const char* client_ip)
{
    /* Track miner */
    ftc_rpc_track_miner(rpc, client_ip);

    /* Parse miner address from params */
    char addr_str[64] = {0};
    extract_param_string(params, 0, addr_str, sizeof(addr_str));

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

static void rpc_getblocksinfo(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    if (!rpc->handlers || !rpc->handlers->get_data_dir || !rpc->handlers->get_best_height) {
        rpc_error(json, -1, "Handler not available", id);
        return;
    }

    const char* data_dir = rpc->handlers->get_data_dir(rpc->handlers->user_data);
    if (!data_dir) {
        rpc_error(json, -1, "Data directory not available", id);
        return;
    }

    /* Build blocks.dat path */
    char blocks_path[512];
    snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", data_dir);

    /* Get file info */
    FILE* f = fopen(blocks_path, "rb");
    if (!f) {
        ftc_json_object_start(json);
        ftc_json_kv_string(json, "jsonrpc", "2.0");
        ftc_json_key(json, "result");
        ftc_json_object_start(json);
        ftc_json_kv_int(json, "blocks", 0);
        ftc_json_kv_int(json, "size", 0);
        ftc_json_kv_bool(json, "available", false);
        ftc_json_object_end(json);
        ftc_json_kv_string(json, "id", id);
        ftc_json_object_end(json);
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);

    uint32_t height = rpc->handlers->get_best_height(rpc->handlers->user_data);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_uint(json, "blocks", height);
    ftc_json_kv_int(json, "size", file_size);
    ftc_json_kv_bool(json, "available", true);
    ftc_json_kv_string(json, "url", "/blocks.dat");
    ftc_json_object_end(json);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_submitblock(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id, const char* client_ip)
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
        ftc_rpc_record_block(rpc, client_ip, false);
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

    /* Record block submission */
    ftc_rpc_record_block(rpc, client_ip, success);

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

static void rpc_getminerstats(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    int64_t now = (int64_t)time(NULL);

    FTC_RPC_MUTEX_LOCK(rpc->miner_mutex);

    /* Count active miners while holding lock */
    int active_count = 0;
    for (int i = 0; i < rpc->miner_count; i++) {
        if (now - rpc->miners[i].last_seen <= FTC_MINER_TIMEOUT) {
            active_count++;
        }
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_int(json, "active", active_count);
    ftc_json_kv_int(json, "total", rpc->miner_count);
    ftc_json_kv_int(json, "timeout_seconds", FTC_MINER_TIMEOUT);

    ftc_json_key(json, "miners");
    ftc_json_array_start(json);

    for (int i = 0; i < rpc->miner_count; i++) {
        ftc_miner_info_t* m = &rpc->miners[i];
        bool is_active = (now - m->last_seen) <= FTC_MINER_TIMEOUT;

        ftc_json_object_start(json);
        ftc_json_kv_string(json, "ip", m->ip);
        ftc_json_kv_bool(json, "active", is_active);
        ftc_json_kv_uint(json, "requests", m->requests);
        ftc_json_kv_uint(json, "blocks_found", m->blocks_found);
        ftc_json_kv_uint(json, "blocks_rejected", m->blocks_rejected);
        ftc_json_kv_int(json, "last_seen_ago", (int)(now - m->last_seen));
        ftc_json_kv_int(json, "first_seen", (int)m->first_seen);
        ftc_json_object_end(json);
    }

    ftc_json_array_end(json);
    ftc_json_object_end(json);

    FTC_RPC_MUTEX_UNLOCK(rpc->miner_mutex);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

/*==============================================================================
 * P2POOL RPC METHODS
 *============================================================================*/

static void rpc_getstratumstats(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    if (!rpc->handlers || !rpc->handlers->get_stratum_stats) {
        rpc_error(json, -32601, "Stratum not enabled", id);
        return;
    }

    int miners = 0;
    double hashrate = 0;
    uint64_t shares = 0, blocks = 0;

    bool ok = rpc->handlers->get_stratum_stats(
        rpc->handlers->user_data, &miners, &hashrate, &shares, &blocks);

    if (!ok) {
        rpc_error(json, -32603, "Stratum error", id);
        return;
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_int(json, "miners", miners);
    ftc_json_kv_double(json, "hashrate", hashrate);
    ftc_json_kv_uint(json, "shares", shares);
    ftc_json_kv_uint(json, "blocks", blocks);
    ftc_json_object_end(json);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getpoolstatus(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* id)
{
    if (!rpc->handlers || !rpc->handlers->p2pool_get_status) {
        rpc_error(json, -32601, "P2Pool not enabled", id);
        return;
    }

    int share_count = 0, miner_count = 0;
    uint64_t total_work = 0;

    bool ok = rpc->handlers->p2pool_get_status(
        rpc->handlers->user_data, &share_count, &miner_count, &total_work);

    if (!ok) {
        rpc_error(json, -32603, "P2Pool error", id);
        return;
    }

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_bool(json, "enabled", true);
    ftc_json_kv_int(json, "share_count", share_count);
    ftc_json_kv_int(json, "miner_count", miner_count);
    ftc_json_kv_uint(json, "total_work", total_work);
    ftc_json_kv_int(json, "pplns_window", 100);
    ftc_json_object_end(json);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_submitshare(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    if (!rpc->handlers || !rpc->handlers->p2pool_submit_share) {
        rpc_error(json, -32601, "P2Pool not enabled", id);
        return;
    }

    /* Parse params: [miner_address, work_done, block_hash_hex] */
    char miner_addr[64] = {0};
    char hash_hex[65] = {0};
    int64_t work = 0;

    /* Simple param parsing - expects ["addr", work, "hash"] */
    const char* p = params;
    while (*p && *p != '"') p++;
    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < 63) miner_addr[i++] = *p++;
    }

    /* Find work value */
    while (*p && (*p < '0' || *p > '9')) p++;
    while (*p >= '0' && *p <= '9') {
        work = work * 10 + (*p - '0');
        p++;
    }

    /* Find hash */
    while (*p && *p != '"') p++;
    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < 64) hash_hex[i++] = *p++;
    }

    if (!miner_addr[0] || work <= 0) {
        rpc_error(json, -32602, "Invalid params: need [address, work, hash]", id);
        return;
    }

    /* Convert hash hex to bytes */
    uint8_t block_hash[32] = {0};
    for (int i = 0; i < 32 && hash_hex[i*2] && hash_hex[i*2+1]; i++) {
        char byte[3] = {hash_hex[i*2], hash_hex[i*2+1], 0};
        block_hash[i] = (uint8_t)strtol(byte, NULL, 16);
    }

    bool ok = rpc->handlers->p2pool_submit_share(
        rpc->handlers->user_data, miner_addr, (uint64_t)work, block_hash);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");
    ftc_json_kv_bool(json, "result", ok);
    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);
}

static void rpc_getpoolpayouts(ftc_rpc_server_t* rpc, ftc_json_t* json, const char* params, const char* id)
{
    if (!rpc->handlers || !rpc->handlers->p2pool_get_payouts) {
        rpc_error(json, -32601, "P2Pool not enabled", id);
        return;
    }

    /* Parse reward from params */
    int64_t reward = 5000000000;  /* Default 50 FTC */
    const char* p = params;
    while (*p && (*p < '0' || *p > '9')) p++;
    if (*p >= '0' && *p <= '9') {
        reward = 0;
        while (*p >= '0' && *p <= '9') {
            reward = reward * 10 + (*p - '0');
            p++;
        }
    }

    /* Get payouts */
    #define MAX_PAYOUTS 100
    char* addresses[MAX_PAYOUTS];
    uint64_t amounts[MAX_PAYOUTS];
    for (int i = 0; i < MAX_PAYOUTS; i++) {
        addresses[i] = malloc(64);
        addresses[i][0] = 0;
    }

    int count = rpc->handlers->p2pool_get_payouts(
        rpc->handlers->user_data, (uint64_t)reward, addresses, amounts, MAX_PAYOUTS);

    ftc_json_object_start(json);
    ftc_json_kv_string(json, "jsonrpc", "2.0");

    ftc_json_key(json, "result");
    ftc_json_object_start(json);
    ftc_json_kv_uint(json, "total_reward", (uint64_t)reward);
    ftc_json_kv_int(json, "payout_count", count);

    ftc_json_key(json, "payouts");
    ftc_json_array_start(json);
    for (int i = 0; i < count; i++) {
        ftc_json_object_start(json);
        ftc_json_kv_string(json, "address", addresses[i]);
        ftc_json_kv_uint(json, "amount", amounts[i]);
        ftc_json_kv_double(json, "ftc", (double)amounts[i] / 100000000.0);
        ftc_json_object_end(json);
    }
    ftc_json_array_end(json);
    ftc_json_object_end(json);

    ftc_json_kv_string(json, "id", id);
    ftc_json_object_end(json);

    for (int i = 0; i < MAX_PAYOUTS; i++) free(addresses[i]);
    #undef MAX_PAYOUTS
}

/*==============================================================================
 * REQUEST HANDLING
 *============================================================================*/

static void process_request(ftc_rpc_server_t* rpc, const char* request, ftc_json_t* response, const char* client_ip)
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
    } else if (strcmp(method, "getpeerinfo") == 0) {
        rpc_getpeerinfo(rpc, response, id);
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
        rpc_getblocktemplate(rpc, response, params ? params : "[]", id, client_ip);
    } else if (strcmp(method, "submitblock") == 0) {
        rpc_submitblock(rpc, response, params ? params : "[]", id, client_ip);
    } else if (strcmp(method, "getblocksinfo") == 0) {
        rpc_getblocksinfo(rpc, response, id);
    } else if (strcmp(method, "getminerstats") == 0) {
        rpc_getminerstats(rpc, response, id);
    } else if (strcmp(method, "getpoolstatus") == 0) {
        rpc_getpoolstatus(rpc, response, id);
    } else if (strcmp(method, "getstratumstats") == 0) {
        rpc_getstratumstats(rpc, response, id);
    } else if (strcmp(method, "submitshare") == 0) {
        rpc_submitshare(rpc, response, params ? params : "[]", id);
    } else if (strcmp(method, "getpoolpayouts") == 0) {
        rpc_getpoolpayouts(rpc, response, params ? params : "[]", id);
    } else {
        rpc_error(response, -32601, "Method not found", id);
    }
}

static void handle_client_with_ip(ftc_rpc_server_t* rpc, ftc_rpc_socket_t client, const char* client_ip)
{
    /* Set receive timeout - keep short to avoid blocking other requests */
#ifdef _WIN32
    DWORD timeout = 500;  /* 500ms */
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  /* 500ms */
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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

    /* Check for GET /blocks.dat request (file download) */
    if (strncmp(request, "GET /blocks.dat", 15) == 0) {
        if (rpc->handlers && rpc->handlers->get_data_dir) {
            const char* data_dir = rpc->handlers->get_data_dir(rpc->handlers->user_data);
            if (data_dir) {
                char blocks_path[512];
                snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", data_dir);

                FILE* f = fopen(blocks_path, "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long file_size = ftell(f);
                    fseek(f, 0, SEEK_SET);

                    char header[512];
                    snprintf(header, sizeof(header),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/octet-stream\r\n"
                             "Content-Disposition: attachment; filename=\"blocks.dat\"\r\n"
                             "Content-Length: %ld\r\n"
                             "Connection: close\r\n"
                             "\r\n",
                             file_size);
                    send(client, header, (int)strlen(header), 0);

                    /* Stream file in chunks */
                    char buffer[65536];
                    size_t bytes_read;
                    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
                        send(client, buffer, (int)bytes_read, 0);
                    }
                    fclose(f);

                    free(request);
                    close_rpc_socket(client);
                    return;
                }
            }
        }
        /* File not found */
        const char* not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client, not_found, (int)strlen(not_found), 0);
        free(request);
        close_rpc_socket(client);
        return;
    }

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
    process_request(rpc, body, response, client_ip);
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
    if (ret < 0) {
#ifdef _WIN32
        printf("[RPC] select() error: %d\n", WSAGetLastError());
#endif
        return;
    }
    if (ret == 0) return;  /* Timeout */

    if (FD_ISSET(rpc->listen_socket, &read_fds)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ftc_rpc_socket_t client = accept(rpc->listen_socket, (struct sockaddr*)&addr, &addr_len);

        if (client != FTC_RPC_INVALID_SOCKET) {
            /* Configure socket for optimal performance */
            configure_client_socket(client);

            /* Extract client IP */
            char client_ip[64] = {0};
            inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

            handle_client_with_ip(rpc, client, client_ip);
        } else {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                printf("[RPC] accept() error: %d\n", err);
            }
#endif
        }
    }
}
