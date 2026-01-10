/**
 * FTC GPU Miner v3.0
 * Clean rewrite with pool (default) and solo modes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define close_socket closesocket
#define usleep(x) Sleep((x)/1000)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
typedef int socket_t;
#define INVALID_SOCKET -1
#define close_socket close
#endif

#include "../src/miner/gpu_miner.h"

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define MINER_VERSION "3.1"
#define STRATUM_PORT 3333
#define MAX_POOLS 8
#define RECV_BUF_SIZE 65536

/* No hardcoded pools - discovered via P2P */

/* ANSI escape codes */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_WHITE   "\033[37m"
#define C_CLEAR   "\033[2J"
#define C_HOME    "\033[H"

/* RPC port for balance queries */
#define RPC_PORT 17318

/*==============================================================================
 * DATA TYPES
 *============================================================================*/

typedef struct {
    char host[256];
    uint16_t port;
    int latency_ms;
    bool active;
} pool_t;

typedef struct {
    socket_t sock;
    char host[256];
    uint16_t port;
    bool connected;
    bool authorized;

    /* Job data */
    char job_id[64];
    uint8_t prevhash[32];
    uint8_t merkle_root[32];
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    char extranonce1[32];
    int extranonce2_size;
    uint64_t extranonce2;
    bool has_job;
    double pool_difficulty;  /* Difficulty from pool */

    /* Stats */
    uint64_t shares_accepted;
    uint64_t shares_rejected;

    /* Buffer */
    char recv_buf[RECV_BUF_SIZE];
    int recv_len;
    int msg_id;
    int last_submit_id;  /* Track ID of last mining.submit */
} stratum_t;

/*==============================================================================
 * GLOBALS
 *============================================================================*/

static volatile bool g_running = true;
static char g_address[128] = {0};
static char g_password[64] = "x";
static bool g_solo_mode = false;
static int g_intensity = 100;
static uint64_t g_device_mask = 0xFFFFFFFFFFFFFFFF;

static pool_t g_pools[MAX_POOLS];
static int g_pool_count = 0;
static int g_active_pool = -1;
static stratum_t g_stratum = {0};

static ftc_gpu_farm_t* g_farm = NULL;
static int64_t g_start_time = 0;
static uint64_t g_total_hashes = 0;
static uint64_t g_blocks_found = 0;

/* Wallet & pool stats */
static double g_wallet_balance = 0.0;
static int64_t g_last_balance_check = 0;
static int g_pool_miners_online = 0;
static int g_pool_blocks_found = 0;
static double g_pool_hashrate = 0.0;
static double g_total_payouts = 0.0;
static int g_payout_count = 0;

/* Network stats */
static uint32_t g_block_height = 0;
static double g_difficulty = 0.0;
static int64_t g_last_block_time = 0;
#define BLOCK_TIME_TARGET 60  /* 60 seconds target block time */

/*==============================================================================
 * UTILITIES
 *============================================================================*/

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

static int64_t get_time_ms(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (int64_t)(now.QuadPart * 1000LL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
#endif
}

static void hex_to_bytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

static void bytes_to_hex(const uint8_t* bytes, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

#ifdef _WIN32
static void enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | 0x0004);
}
#endif

/*==============================================================================
 * NETWORK
 *============================================================================*/

static bool net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

static int measure_latency(const char* host, uint16_t port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return 9999;

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 9999;
    }

    /* Set non-blocking mode */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    fcntl(sock, F_SETFL, O_NONBLOCK);
#endif

    int64_t start = get_time_ms();
    int ret = connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == 0) {
        /* Connected immediately */
        int64_t latency = get_time_ms() - start;
        close_socket(sock);
        return (latency < 1) ? 1 : (int)latency;
    }

    /* Wait for connection with 1 second timeout */
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    struct timeval tv = {1, 0};

    ret = select((int)sock + 1, NULL, &writefds, NULL, &tv);
    int64_t latency = get_time_ms() - start;

    if (ret > 0 && FD_ISSET(sock, &writefds)) {
        /* Check if actually connected */
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        close_socket(sock);
        if (err == 0) {
            return (latency < 1) ? 1 : (int)latency;
        }
    }

    close_socket(sock);
    return 9999;
}

/*==============================================================================
 * STRATUM PROTOCOL
 *============================================================================*/

static bool stratum_send(stratum_t* s, const char* msg) {
    size_t len = strlen(msg);
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s\n", msg);
    return send(s->sock, buf, (int)strlen(buf), 0) > 0;
}

static bool stratum_recv_line(stratum_t* s, char* line, size_t size) {
    while (1) {
        char* nl = memchr(s->recv_buf, '\n', s->recv_len);
        if (nl) {
            size_t len = nl - s->recv_buf;
            if (len >= size) len = size - 1;
            memcpy(line, s->recv_buf, len);
            line[len] = '\0';

            int remain = s->recv_len - (int)(nl - s->recv_buf) - 1;
            if (remain > 0) memmove(s->recv_buf, nl + 1, remain);
            s->recv_len = remain;
            return true;
        }

        if (s->recv_len >= RECV_BUF_SIZE - 1) return false;

        int n = recv(s->sock, s->recv_buf + s->recv_len,
                     RECV_BUF_SIZE - s->recv_len - 1, 0);
        if (n <= 0) return false;
        s->recv_len += n;
    }
}

static void stratum_parse_job(stratum_t* s, const char* line) {
    /* Parse mining.notify: [job_id, prevhash, coinb1, coinb2, [], version, nbits, ntime, clean] */
    const char* p = strstr(line, "\"params\":");
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;

    /* job_id */
    p = strchr(p, '"'); if (!p) return; p++;
    const char* end = strchr(p, '"'); if (!end) return;
    size_t len = end - p;
    if (len >= sizeof(s->job_id)) len = sizeof(s->job_id) - 1;
    memcpy(s->job_id, p, len);
    s->job_id[len] = '\0';

    /* prevhash */
    p = strchr(end + 1, '"'); if (!p) return; p++;
    end = strchr(p, '"'); if (!end) return;
    if (end - p >= 64) hex_to_bytes(p, s->prevhash, 32);

    /* coinb1 (merkle_root for FTC) */
    p = strchr(end + 1, '"'); if (!p) return; p++;
    end = strchr(p, '"'); if (!end) return;
    if (end - p >= 64) hex_to_bytes(p, s->merkle_root, 32);

    /* Skip coinb2 and merkle branches */
    p = strstr(end, "],");
    if (!p) return;

    /* version */
    p = strchr(p, '"'); if (!p) return; p++;
    s->version = strtoul(p, NULL, 16);
    p = strchr(p, '"'); if (!p) return;  /* find closing quote */

    /* nbits */
    p = strchr(p + 1, '"'); if (!p) return; p++;
    s->nbits = strtoul(p, NULL, 16);
    p = strchr(p, '"'); if (!p) return;  /* find closing quote */

    /* ntime */
    p = strchr(p + 1, '"'); if (!p) return; p++;
    s->ntime = strtoul(p, NULL, 16);

    s->has_job = true;
}

static void stratum_handle_msg(stratum_t* s, const char* line) {
    if (strstr(line, "mining.notify")) {
        stratum_parse_job(s, line);
    } else if (strstr(line, "mining.set_difficulty")) {
        /* Parse difficulty from params:[value] */
        const char* p = strstr(line, "\"params\":");
        if (p) {
            p = strchr(p, '[');
            if (p) {
                s->pool_difficulty = atof(p + 1);
                if (s->pool_difficulty < 1.0) s->pool_difficulty = 1.0;
            }
        }
    } else if (strstr(line, "\"result\":true") && strstr(line, "\"id\":")) {
        /* Check if this is a response to our submit */
        const char* id_str = strstr(line, "\"id\":");
        if (id_str) {
            int resp_id = atoi(id_str + 5);
            if (resp_id == s->last_submit_id) {
                s->shares_accepted++;
            }
        }
    } else if (strstr(line, "\"result\":false") || strstr(line, "\"error\":")) {
        const char* id_str = strstr(line, "\"id\":");
        if (id_str && !strstr(line, "\"id\":null")) {
            int resp_id = atoi(id_str + 5);
            if (resp_id == s->last_submit_id) {
                s->shares_rejected++;
            }
        }
    }
}

static bool stratum_poll(stratum_t* s) {
    if (!s->connected) return false;

    /* Non-blocking receive */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s->sock, FIONBIO, &mode);
#else
    fcntl(s->sock, F_SETFL, O_NONBLOCK);
#endif

    char line[4096];
    while (1) {
        int n = recv(s->sock, s->recv_buf + s->recv_len,
                     RECV_BUF_SIZE - s->recv_len - 1, 0);
        if (n > 0) s->recv_len += n;
        else if (n == 0) { s->connected = false; return false; }

        char* nl = memchr(s->recv_buf, '\n', s->recv_len);
        if (!nl) break;

        size_t len = nl - s->recv_buf;
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, s->recv_buf, len);
        line[len] = '\0';

        int remain = s->recv_len - (int)(nl - s->recv_buf) - 1;
        if (remain > 0) memmove(s->recv_buf, nl + 1, remain);
        s->recv_len = remain;

        stratum_handle_msg(s, line);
    }
    return true;
}

static bool stratum_connect(stratum_t* s) {
    /* Save host/port before clearing */
    char host[256];
    uint16_t port = s->port;
    strncpy(host, s->host, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    /* Clear state */
    memset(s, 0, sizeof(*s));
    s->sock = INVALID_SOCKET;
    s->pool_difficulty = 32.0;  /* Default difficulty for GPU miners */

    /* Restore host/port */
    strncpy(s->host, host, sizeof(s->host) - 1);
    s->port = port;

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", s->port);

    if (getaddrinfo(s->host, port_str, &hints, &res) != 0) return false;

    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return false;
    }

    /* Timeout */
#ifdef _WIN32
    DWORD timeout = 10000;
    setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {10, 0};
    setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(s->sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close_socket(s->sock);
        s->sock = INVALID_SOCKET;
        return false;
    }
    freeaddrinfo(res);

    s->connected = true;
    s->msg_id = 1;
    return true;
}

static bool stratum_subscribe(stratum_t* s) {
    char msg[256];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.subscribe\",\"params\":[\"FTC-Miner/%s\"]}",
        s->msg_id++, MINER_VERSION);

    if (!stratum_send(s, msg)) return false;

    char line[4096];
    if (!stratum_recv_line(s, line, sizeof(line))) return false;

    /* Parse extranonce1 */
    char* en1 = strstr(line, "\",\"");
    if (en1) {
        en1 += 3;
        char* en1_end = strchr(en1, '"');
        if (en1_end && en1_end - en1 < (int)sizeof(s->extranonce1)) {
            memcpy(s->extranonce1, en1, en1_end - en1);
        }
    }

    /* Parse extranonce2_size */
    char* last = strrchr(line, ',');
    if (last) s->extranonce2_size = atoi(last + 1);
    if (s->extranonce2_size <= 0) s->extranonce2_size = 4;

    return strstr(line, "\"result\":") != NULL;
}

static bool stratum_authorize(stratum_t* s, const char* worker, const char* pass) {
    char msg[512];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}",
        s->msg_id++, worker, pass);

    if (!stratum_send(s, msg)) return false;

    char line[4096];
    if (!stratum_recv_line(s, line, sizeof(line))) return false;

    if (strstr(line, "\"result\":true")) {
        s->authorized = true;

        /* Process buffered messages (difficulty + job) */
        while (s->recv_len > 0) {
            char* nl = memchr(s->recv_buf, '\n', s->recv_len);
            if (!nl) break;

            size_t len = nl - s->recv_buf;
            if (len >= sizeof(line)) len = sizeof(line) - 1;
            memcpy(line, s->recv_buf, len);
            line[len] = '\0';

            int remain = s->recv_len - (int)(nl - s->recv_buf) - 1;
            if (remain > 0) memmove(s->recv_buf, nl + 1, remain);
            s->recv_len = remain;

            stratum_handle_msg(s, line);
        }
        return true;
    }
    return false;
}

static void stratum_submit(stratum_t* s, uint32_t nonce, uint32_t ntime) {
    char en2_hex[32] = {0};
    for (int i = 0; i < s->extranonce2_size && i < 8; i++) {
        sprintf(en2_hex + i * 2, "%02x", (uint8_t)(s->extranonce2 >> (i * 8)));
    }

    char msg[512];
    s->last_submit_id = s->msg_id;  /* Track this submit's ID */
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%08x\",\"%08x\"]}",
        s->msg_id++, g_address, s->job_id, en2_hex, ntime, nonce);

    stratum_send(s, msg);
}

static void stratum_report_hashrate(stratum_t* s, double hashrate) {
    char msg[256];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.hashrate\",\"params\":[%.0f]}",
        s->msg_id++, hashrate);
    stratum_send(s, msg);
}

static void stratum_disconnect(stratum_t* s) {
    if (s->sock != INVALID_SOCKET) {
        close_socket(s->sock);
        s->sock = INVALID_SOCKET;
    }
    s->connected = false;
    s->authorized = false;
    s->has_job = false;
}

/*==============================================================================
 * RPC CLIENT (for wallet balance & pool stats)
 *============================================================================*/

static bool rpc_request(const char* host, const char* method, const char* params, char* response, size_t resp_size) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", RPC_PORT);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return false;

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return false;
    }

#ifdef _WIN32
    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close_socket(sock);
        return false;
    }
    freeaddrinfo(res);

    /* Build JSON-RPC request */
    char body[512];
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}", method, params);

    char request[1024];
    snprintf(request, sizeof(request),
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        host, RPC_PORT, (int)strlen(body), body);

    if (send(sock, request, (int)strlen(request), 0) <= 0) {
        close_socket(sock);
        return false;
    }

    char buf[4096];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = recv(sock, buf + total, (int)sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    close_socket(sock);

    /* Extract JSON body */
    char* json = strstr(buf, "\r\n\r\n");
    if (json) {
        json += 4;
        strncpy(response, json, resp_size - 1);
        response[resp_size - 1] = '\0';
        return true;
    }
    return false;
}

static void update_wallet_balance(void) {
    int64_t now = get_time_ms();
    if (now - g_last_balance_check < 10000) return; /* Every 10 seconds */
    g_last_balance_check = now;

    char params[256];
    snprintf(params, sizeof(params), "[\"%s\"]", g_address);

    char response[2048];
    if (!rpc_request(g_pools[g_active_pool].host, "getbalance", params, response, sizeof(response))) {
        return;
    }

    /* Parse balance from response */
    char* result = strstr(response, "\"result\":");
    if (result) {
        result += 9;
        g_wallet_balance = atof(result);
    }
}

static void update_pool_stats(void) {
    static int64_t last_check = 0;
    int64_t now = get_time_ms();
    if (now - last_check < 5000) return; /* Every 5 seconds */
    last_check = now;

    char response[4096];

    /* Get stratum stats (miners, hashrate, shares, blocks) */
    if (rpc_request(g_pools[g_active_pool].host, "getstratumstats", "[]", response, sizeof(response))) {
        char* p = strstr(response, "\"miners\":");
        if (p) g_pool_miners_online = atoi(p + 9);

        p = strstr(response, "\"hashrate\":");
        if (p) g_pool_hashrate = atof(p + 11);

        p = strstr(response, "\"blocks\":");
        if (p) g_pool_blocks_found = atoi(p + 9);
    }

    /* Get network info (height, difficulty) from getinfo */
    if (rpc_request(g_pools[g_active_pool].host, "getinfo", "[]", response, sizeof(response))) {
        char* p = strstr(response, "\"blocks\":");
        if (p) {
            uint32_t new_height = (uint32_t)atoi(p + 9);
            /* Only reset timer when height increases (not on first fetch) */
            if (g_block_height > 0 && new_height > g_block_height) {
                g_last_block_time = now;  /* New block found */
            }
            g_block_height = new_height;
        }

        p = strstr(response, "\"difficulty\":");
        if (p) g_difficulty = atof(p + 13);
    }


    /* Get payouts for this address */
    char params[256];
    snprintf(params, sizeof(params), "[\"%s\"]", g_address);
    if (rpc_request(g_pools[g_active_pool].host, "getpoolpayouts", params, response, sizeof(response))) {
        char* p = strstr(response, "\"total\":");
        if (p) g_total_payouts = atof(p + 8);

        p = strstr(response, "\"count\":");
        if (p) g_payout_count = atoi(p + 8);
    }
}

/*==============================================================================
 * POOL MANAGEMENT
 *============================================================================*/

static void add_pool(const char* host, uint16_t port) {
    if (g_pool_count >= MAX_POOLS) return;

    /* Check for duplicates */
    for (int i = 0; i < g_pool_count; i++) {
        if (strcmp(g_pools[i].host, host) == 0 && g_pools[i].port == port) return;
    }

    strncpy(g_pools[g_pool_count].host, host, sizeof(g_pools[0].host) - 1);
    g_pools[g_pool_count].port = port;
    g_pools[g_pool_count].active = true;
    g_pool_count++;
}

static void discover_peers(const char* seed_host) {
    /* Get peer list from seed node via RPC getpeerinfo */
    char response[8192];
    if (!rpc_request(seed_host, "getpeerinfo", "[]", response, sizeof(response))) {
        printf("Warning: Could not get peer list from %s\n", seed_host);
        return;
    }

    /* Parse peer addresses from JSON response */
    /* Format: {"result":[{"addr": "IP", "port": PORT}, ...]} */
    char* p = response;
    while ((p = strstr(p, "\"addr\"")) != NULL) {
        p += 6;  /* Skip "addr" */
        /* Skip : and whitespace */
        while (*p == ':' || *p == ' ' || *p == '\t') p++;
        if (*p != '"') continue;
        p++;  /* Skip opening quote */

        char* end = strchr(p, '"');
        if (!end) break;

        char addr[256];
        int len = (int)(end - p);
        if (len > 0 && len < (int)sizeof(addr) - 1) {
            memcpy(addr, p, len);
            addr[len] = '\0';
            /* Add peer with stratum port */
            add_pool(addr, STRATUM_PORT);
        }
        p = end + 1;
    }
}

static void init_pools(const char* seed_node) {
    g_pool_count = 0;

    if (!seed_node || !seed_node[0]) {
        printf("Error: No seed node specified. Use -node <IP:PORT>\n");
        return;
    }

    /* Parse seed node */
    char seed_host[256];
    strncpy(seed_host, seed_node, sizeof(seed_host) - 1);
    seed_host[sizeof(seed_host) - 1] = '\0';

    uint16_t seed_port = STRATUM_PORT;
    char* colon = strchr(seed_host, ':');
    if (colon) {
        *colon = '\0';
        seed_port = (uint16_t)atoi(colon + 1);
    }

    /* Add seed node first */
    add_pool(seed_host, seed_port);

    /* Discover other peers from seed node */
    printf("Discovering peers from %s...\n", seed_host);
    discover_peers(seed_host);

    printf("Found %d nodes in network\n", g_pool_count);
}

static int select_best_pool(void) {
    int best = -1, best_lat = 99999;

    for (int i = 0; i < g_pool_count; i++) {
        if (!g_pools[i].active) continue;
        printf("  Testing %s:%d... ", g_pools[i].host, g_pools[i].port);
        fflush(stdout);
        g_pools[i].latency_ms = measure_latency(g_pools[i].host, g_pools[i].port);
        printf("%d ms\n", g_pools[i].latency_ms);
        if (g_pools[i].latency_ms < best_lat) {
            best_lat = g_pools[i].latency_ms;
            best = i;
        }
    }
    return best;
}

static bool connect_pool(int idx) {
    if (idx < 0 || idx >= g_pool_count) return false;

    strncpy(g_stratum.host, g_pools[idx].host, sizeof(g_stratum.host) - 1);
    g_stratum.port = g_pools[idx].port;

    if (!stratum_connect(&g_stratum)) return false;
    if (!stratum_subscribe(&g_stratum)) { stratum_disconnect(&g_stratum); return false; }
    if (!stratum_authorize(&g_stratum, g_address, g_password)) { stratum_disconnect(&g_stratum); return false; }

    g_active_pool = idx;
    return true;
}

/*==============================================================================
 * DISPLAY
 *============================================================================*/

static void format_hashrate(double hr, char* buf, size_t size) {
    if (hr >= 1e12) snprintf(buf, size, "%.2f TH/s", hr / 1e12);
    else if (hr >= 1e9) snprintf(buf, size, "%.2f GH/s", hr / 1e9);
    else if (hr >= 1e6) snprintf(buf, size, "%.2f MH/s", hr / 1e6);
    else if (hr >= 1e3) snprintf(buf, size, "%.2f KH/s", hr / 1e3);
    else snprintf(buf, size, "%.0f H/s", hr);
}

static void draw_display(void) {
    double elapsed = (get_time_ms() - g_start_time) / 1000.0;
    if (elapsed < 0.1) elapsed = 0.1;

    double hashrate = ftc_gpu_farm_get_hashrate(g_farm);

    char hr_str[32], pool_hr_str[32];
    format_hashrate(hashrate, hr_str, sizeof(hr_str));
    format_hashrate(g_pool_hashrate, pool_hr_str, sizeof(pool_hr_str));

    int hours = (int)elapsed / 3600;
    int mins = ((int)elapsed % 3600) / 60;
    int secs = (int)elapsed % 60;

    /* Calculate share rate */
    double share_rate = (elapsed > 0) ? (g_stratum.shares_accepted * 60.0 / elapsed) : 0;

    /* Calculate countdown to next block */
    int64_t now = get_time_ms();
    int time_since_block = (g_last_block_time > 0) ? (int)((now - g_last_block_time) / 1000) : 0;
    int countdown = BLOCK_TIME_TARGET - time_since_block;

    printf(C_HOME);

    /* Header */
    printf(C_CYAN "+==============================================================================+\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  " C_BOLD C_WHITE "FTC GPU Miner" C_RESET " " C_YELLOW "v%s" C_RESET "                                        " C_GREEN "MINING" C_RESET "  " C_CYAN "|\n" C_RESET, MINER_VERSION);
    printf(C_CYAN "+==============================================================================+\n" C_RESET);

    /* Pool Info */
    printf(C_CYAN "|" C_RESET "  " C_BOLD "POOL" C_RESET "                                                                     " C_CYAN "|\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  Server    : " C_GREEN "%-20s" C_RESET " Port: " C_WHITE "%-5d" C_RESET " Latency: " C_YELLOW "%3d ms" C_RESET "          " C_CYAN "|\n" C_RESET,
           g_pools[g_active_pool].host, g_pools[g_active_pool].port, g_pools[g_active_pool].latency_ms);
    printf(C_CYAN "|" C_RESET "  Job ID    : " C_WHITE "%-52s" C_RESET "      " C_CYAN "|\n" C_RESET, g_stratum.job_id);
    printf(C_CYAN "+------------------------------------------------------------------------------+\n" C_RESET);

    /* Miner Stats */
    printf(C_CYAN "|" C_RESET "  " C_BOLD "MINER STATS" C_RESET "                                                              " C_CYAN "|\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  Hashrate  : " C_GREEN C_BOLD "%-14s" C_RESET "   Uptime: " C_WHITE "%02d:%02d:%02d" C_RESET "                        " C_CYAN "|\n" C_RESET,
           hr_str, hours, mins, secs);
    printf(C_CYAN "|" C_RESET "  Accepted  : " C_GREEN "%-8llu" C_RESET "         Rejected: " C_RED "%-8llu" C_RESET "                    " C_CYAN "|\n" C_RESET,
           (unsigned long long)g_stratum.shares_accepted, (unsigned long long)g_stratum.shares_rejected);
    printf(C_CYAN "|" C_RESET "  Share Rate: " C_WHITE "%.2f/min" C_RESET "        Blocks Found: " C_YELLOW "%-6llu" C_RESET "                   " C_CYAN "|\n" C_RESET,
           share_rate, (unsigned long long)g_blocks_found);
    printf(C_CYAN "+------------------------------------------------------------------------------+\n" C_RESET);

    /* Network Stats */
    printf(C_CYAN "|" C_RESET "  " C_BOLD "NETWORK" C_RESET "                                                                  " C_CYAN "|\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  Height    : " C_GREEN "%-8u" C_RESET "         Difficulty: " C_YELLOW "%-16.2f" C_RESET "    " C_CYAN "|\n" C_RESET,
           g_block_height, g_difficulty);
    if (g_last_block_time == 0) {
        printf(C_CYAN "|" C_RESET "  Next Block: " C_WHITE "waiting..." C_RESET "       (tracking after first block)            " C_CYAN "|\n" C_RESET);
    } else if (countdown > 0) {
        printf(C_CYAN "|" C_RESET "  Next Block: " C_GREEN C_BOLD "~%02d:%02d" C_RESET "           (estimated countdown)                  " C_CYAN "|\n" C_RESET,
               countdown / 60, countdown % 60);
    } else {
        printf(C_CYAN "|" C_RESET "  Next Block: " C_YELLOW C_BOLD "ANY MOMENT" C_RESET "       (overdue +%ds)                          " C_CYAN "|\n" C_RESET,
               -countdown);
    }
    printf(C_CYAN "+------------------------------------------------------------------------------+\n" C_RESET);

    /* Pool Stats */
    printf(C_CYAN "|" C_RESET "  " C_BOLD "POOL" C_RESET "                                                                     " C_CYAN "|\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  Miners    : " C_GREEN "%-8d" C_RESET "         Pool Hashrate: " C_WHITE "%-14s" C_RESET "      " C_CYAN "|\n" C_RESET,
           g_pool_miners_online, pool_hr_str);
    printf(C_CYAN "|" C_RESET "  Pool Blks : " C_YELLOW "%-8d" C_RESET "         (found by this pool)                   " C_CYAN "|\n" C_RESET,
           g_pool_blocks_found);
    printf(C_CYAN "+------------------------------------------------------------------------------+\n" C_RESET);

    /* Wallet */
    printf(C_CYAN "|" C_RESET "  " C_BOLD "WALLET" C_RESET "                                                                   " C_CYAN "|\n" C_RESET);
    printf(C_CYAN "|" C_RESET "  Address   : " C_MAGENTA "%-52s" C_RESET "      " C_CYAN "|\n" C_RESET, g_address);
    printf(C_CYAN "|" C_RESET "  Balance   : " C_GREEN C_BOLD "%-18.8f" C_RESET " FTC                                " C_CYAN "|\n" C_RESET, g_wallet_balance);
    printf(C_CYAN "|" C_RESET "  Payouts   : " C_YELLOW "%-18.8f" C_RESET " FTC  (" C_WHITE "%d" C_RESET " payments)          " C_CYAN "|\n" C_RESET,
           g_total_payouts, g_payout_count);
    printf(C_CYAN "+==============================================================================+\n" C_RESET);

    /* Status line */
    if (g_stratum.has_job) {
        printf(C_GREEN " [MINING]" C_RESET " Working on job...\n");
    } else {
        printf(C_YELLOW " [WAITING]" C_RESET " Waiting for new job...\n");
    }

    fflush(stdout);
}

/*==============================================================================
 * MINING
 *============================================================================*/

static void mine_pool(void) {
    char current_job[64] = {0};
    int64_t last_display = 0;
    int64_t last_hashrate_report = 0;

    while (g_running) {
        /* Check connection */
        if (!g_stratum.connected) {
            printf("Reconnecting...\n");
            stratum_disconnect(&g_stratum);

            for (int i = 0; i < g_pool_count && g_running; i++) {
                int idx = (g_active_pool + 1 + i) % g_pool_count;
                if (connect_pool(idx)) {
                    printf(C_CLEAR);
                    break;
                }
                usleep(2000000);
            }
            if (!g_stratum.connected) {
                usleep(5000000);
                continue;
            }
        }

        /* Wait for job */
        if (!g_stratum.has_job) {
            stratum_poll(&g_stratum);
            usleep(100000);
            continue;
        }

        /* New job? */
        if (strcmp(current_job, g_stratum.job_id) != 0) {
            strncpy(current_job, g_stratum.job_id, sizeof(current_job) - 1);
            g_stratum.extranonce2++;
        }

        /* Build header */
        uint8_t header[80];
        memset(header, 0, 80);
        memcpy(header, &g_stratum.version, 4);
        memcpy(header + 4, g_stratum.prevhash, 32);
        memcpy(header + 36, g_stratum.merkle_root, 32);
        memcpy(header + 68, &g_stratum.ntime, 4);
        memcpy(header + 72, &g_stratum.nbits, 4);

        /* Calculate share target based on pool difficulty */
        /* Base diff 1: target[27-29] = 0x0fffff */
        /* Higher diff = smaller target (divide by difficulty) */
        uint8_t target[32] = {0};
        double diff = g_stratum.pool_difficulty;
        if (diff < 1.0) diff = 1.0;

        /* Base target value for diff 1 = 0x0fffff (at bytes 27-29) */
        uint64_t base_target = 0x0fffffULL;
        uint64_t scaled_target = (uint64_t)(base_target / diff);

        /* Store in little-endian at bytes 27+ */
        target[27] = (uint8_t)(scaled_target & 0xff);
        target[28] = (uint8_t)((scaled_target >> 8) & 0xff);
        target[29] = (uint8_t)((scaled_target >> 16) & 0xff);
        target[30] = (uint8_t)((scaled_target >> 24) & 0xff);

        /* Mine */
        ftc_gpu_farm_set_work(g_farm, header, target);
        ftc_gpu_result_t result = ftc_gpu_farm_mine(g_farm);

        /* Poll for new jobs */
        stratum_poll(&g_stratum);

        /* Submit if found */
        if (result.found) {
            stratum_submit(&g_stratum, result.nonce, g_stratum.ntime);
            g_blocks_found++;
            g_stratum.extranonce2++;
        }

        /* Update display */
        int64_t now = get_time_ms();
        if (now - last_display >= 500) {
            /* Update stats from RPC (rate-limited internally) */
            update_wallet_balance();
            update_pool_stats();

            draw_display();
            last_display = now;
        }

        /* Report hashrate to pool every 10 seconds */
        if (now - last_hashrate_report >= 10000) {
            double hashrate = ftc_gpu_farm_get_hashrate(g_farm);
            stratum_report_hashrate(&g_stratum, hashrate);
            last_hashrate_report = now;
        }
    }
}

/*==============================================================================
 * MAIN
 *============================================================================*/

static void print_help(void) {
    printf("FTC GPU Miner v%s\n\n", MINER_VERSION);
    printf("Usage: ftc-miner-gpu -address <WALLET> -node <IP> [options]\n\n");
    printf("Options:\n");
    printf("  -address <addr>   Mining reward address (required)\n");
    printf("  -node <host:port> Seed node to connect (required)\n");
    printf("  -solo             Solo mining mode (not implemented)\n");
    printf("  -intensity <1-100> Mining intensity (default: 100)\n");
    printf("  -devices <0,1,2>  GPU devices to use\n");
    printf("  -list             List available GPUs\n");
    printf("  -help             Show this help\n");
    printf("\nExample:\n");
    printf("  ftc-miner-gpu -address FTC1abc... -node 15.164.228.225\n");
}

int main(int argc, char** argv) {
    char seed_node[256] = {0};
    bool list_devices = false;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-address") == 0 && i + 1 < argc) {
            strncpy(g_address, argv[++i], sizeof(g_address) - 1);
        } else if (strcmp(argv[i], "-node") == 0 && i + 1 < argc) {
            strncpy(seed_node, argv[++i], sizeof(seed_node) - 1);
        } else if (strcmp(argv[i], "-solo") == 0) {
            g_solo_mode = true;
        } else if (strcmp(argv[i], "-intensity") == 0 && i + 1 < argc) {
            g_intensity = atoi(argv[++i]);
            if (g_intensity < 1) g_intensity = 1;
            if (g_intensity > 100) g_intensity = 100;
        } else if (strcmp(argv[i], "-devices") == 0 && i + 1 < argc) {
            g_device_mask = 0;
            char* p = argv[++i];
            while (*p) {
                if (*p >= '0' && *p <= '9') {
                    g_device_mask |= (1ULL << (*p - '0'));
                }
                p++;
            }
        } else if (strcmp(argv[i], "-list") == 0) {
            list_devices = true;
        } else if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
    }

#ifdef _WIN32
    enable_ansi();
#endif

    /* Initialize GPU */
    int gpu_count = ftc_gpu_init();
    if (gpu_count <= 0) {
        fprintf(stderr, "Error: No GPUs found. Make sure CUDA drivers are installed.\n");
        return 1;
    }

    if (list_devices) {
        ftc_gpu_print_devices();
        ftc_gpu_shutdown();
        return 0;
    }

    if (!g_address[0]) {
        fprintf(stderr, "Error: Mining address required (-address)\n");
        print_help();
        return 1;
    }

    if (!seed_node[0]) {
        fprintf(stderr, "Error: Seed node required (-node)\n");
        print_help();
        return 1;
    }

    /* Initialize */
    signal(SIGINT, signal_handler);
    net_init();

    uint32_t batch = (FTC_GPU_BATCH_SIZE * g_intensity) / 100;
    g_farm = ftc_gpu_farm_new(g_device_mask, batch);
    if (!g_farm) {
        fprintf(stderr, "Error: Failed to create GPU farm\n");
        ftc_gpu_shutdown();
        return 1;
    }

    if (g_solo_mode) {
        printf("Solo mode not implemented yet\n");
        ftc_gpu_farm_free(g_farm);
        ftc_gpu_shutdown();
        return 1;
    }

    /* Pool mode - discover nodes from seed */
    init_pools(seed_node);

    printf("Selecting best node by latency...\n");
    int best = select_best_pool();
    if (best < 0) {
        fprintf(stderr, "Error: No nodes available\n");
        ftc_gpu_farm_free(g_farm);
        ftc_gpu_shutdown();
        return 1;
    }

    printf("Pool: %s:%d (%dms)\n", g_pools[best].host, g_pools[best].port, g_pools[best].latency_ms);

    if (!connect_pool(best)) {
        fprintf(stderr, "Error: Failed to connect to pool\n");
        ftc_gpu_farm_free(g_farm);
        ftc_gpu_shutdown();
        return 1;
    }

    printf("Connected! Starting mining...\n");
    usleep(1000000);

    g_start_time = get_time_ms();
    printf(C_CLEAR);

    mine_pool();

    /* Cleanup */
    stratum_disconnect(&g_stratum);
    ftc_gpu_farm_free(g_farm);
    ftc_gpu_shutdown();

    printf("\nMiner stopped.\n");
    return 0;
}
