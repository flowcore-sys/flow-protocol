/**
 * FTC GPU Miner - High-Performance Mining Client
 *
 * Features:
 * - NVIDIA (CUDA) and AMD (OpenCL) support
 * - Multi-GPU mining for farms
 * - Auto DNS seed discovery
 * - Node latency monitoring
 * - Rigel-style real-time display
 *
 * Usage: ftc-miner-gpu -address <addr> [-devices <0,1,2>]
 */

#include "../include/ftc.h"
#include "../src/core/block.h"
#include "../src/crypto/keccak256.h"
#include "../src/crypto/keys.h"
#include "../src/miner/gpu_miner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET miner_socket_t;
#define MINER_INVALID_SOCKET INVALID_SOCKET
#define usleep(x) Sleep((x)/1000)

static void enable_ansi_colors(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
typedef int miner_socket_t;
#define MINER_INVALID_SOCKET -1
#define enable_ansi_colors() ((void)0)
#endif

/*==============================================================================
 * SOCKET HELPERS
 *============================================================================*/

static inline void close_socket(miner_socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

static inline miner_socket_t create_tcp_socket(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static inline void set_socket_nonblocking(miner_socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

static inline int socket_would_block(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static void bytes_to_hex(const uint8_t* data, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
}

/*==============================================================================
 * ANSI COLORS (Rigel-style)
 *============================================================================*/

#define C_RESET     "\x1b[0m"
#define C_BOLD      "\x1b[1m"
#define C_DIM       "\x1b[2m"
#define C_BLACK     "\x1b[30m"
#define C_RED       "\x1b[31m"
#define C_GREEN     "\x1b[32m"
#define C_YELLOW    "\x1b[33m"
#define C_BLUE      "\x1b[34m"
#define C_MAGENTA   "\x1b[35m"
#define C_CYAN      "\x1b[36m"
#define C_WHITE     "\x1b[37m"
#define C_GRAY      "\x1b[90m"

/* Background colors */
#define C_BG_GREEN  "\x1b[42m"
#define C_BG_BLUE   "\x1b[44m"
#define C_BG_BLACK  "\x1b[40m"

/* Cursor control */
#define C_CLEAR     "\x1b[2J"
#define C_HOME      "\x1b[H"
#define C_HIDE_CUR  "\x1b[?25l"
#define C_SHOW_CUR  "\x1b[?25h"
#define C_SAVE_CUR  "\x1b[s"
#define C_REST_CUR  "\x1b[u"
#define C_CLR_LINE  "\x1b[2K"

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define MINER_VERSION       "2.5.0"
#define DEFAULT_POOL        "pool.flowprotocol.net:3333"
#define MINER_NAME          "FTC-GPU-Miner"
#define MAX_NODES           16
#define RPC_PORT            17318
#define LATENCY_CHECK_INTERVAL  30000
#define STRATUM_PORT        3333

/*==============================================================================
 * STRATUM PROTOCOL (Pool Mining)
 *============================================================================*/

typedef enum {
    MINING_MODE_SOLO,
    MINING_MODE_POOL
} mining_mode_t;

typedef struct {
    miner_socket_t sock;
    char host[256];
    uint16_t port;
    char worker[128];       /* wallet address */
    char password[64];      /* optional */
    bool connected;
    bool authorized;
    bool subscribed;

    /* Current job from pool */
    char job_id[64];
    uint8_t prevhash[32];
    uint8_t coinb1[1024];
    size_t coinb1_len;
    uint8_t coinb2[1024];
    size_t coinb2_len;
    char extranonce1[32];
    int extranonce2_size;
    uint32_t version;
    uint32_t ntime;
    uint32_t nbits;
    double target_diff;
    bool has_job;

    /* Extranonce2 counter */
    uint64_t extranonce2;

    /* Stats */
    uint64_t shares_sent;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    uint64_t shares_stale;
    time_t connect_time;
    time_t last_share_time;
    int latency_ms;
    uint64_t jobs_received;

    /* Receive buffer */
    char recv_buf[65536];
    int recv_len;

    /* Message ID counter */
    int msg_id;
} stratum_ctx_t;

static stratum_ctx_t g_stratum = {0};
static mining_mode_t g_mining_mode = MINING_MODE_POOL;  /* Pool by default */
static char g_pool_url[256] = "pool.flowprotocol.net:3333";
static char g_pool_pass[64] = "x";

/*==============================================================================
 * POOL STATS (from HTTP API)
 *============================================================================*/

typedef struct {
    int miners_online;
    double pool_hashrate;
    char pool_hashrate_str[32];
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    int blocks_found;
    int64_t last_update;
    bool valid;
} pool_stats_t;

static pool_stats_t g_pool_stats = {0};
#define POOL_STATS_INTERVAL 5000  /* Update every 5 seconds */

static const char* DNS_SEEDS[] = {
    "seed.flowprotocol.net",
    "seed1.flowprotocol.net",
    NULL
};

/*==============================================================================
 * NODE MANAGEMENT
 *============================================================================*/

typedef struct {
    char host[256];
    char ip[64];
    uint16_t port;
    int latency_ms;
    bool active;
    bool connected;
    uint32_t height;
    int failures;
} node_info_t;

static node_info_t g_nodes[MAX_NODES];
static int g_node_count = 0;
static int g_active_node = -1;

/*==============================================================================
 * GLOBALS
 *============================================================================*/

static volatile bool g_running = true;
static char g_miner_address[64] = {0};
static char g_custom_node[256] = {0};  /* Custom node host:port */
static bool g_color = true;
static uint32_t g_device_mask = 0;  /* 0 = all devices */

/* Statistics */
static int64_t g_start_time = 0;
static uint64_t g_total_hashes = 0;
static uint64_t g_blocks_found = 0;
static uint64_t g_blocks_accepted = 0;
static uint32_t g_current_height = 0;
static int g_peer_count = 0;
static double g_difficulty = 1.0;
static char g_last_block_hash[17] = {0};

/* GPU Farm */
static ftc_gpu_farm_t* g_farm = NULL;

/* Log buffer for static display */
#define LOG_BUFFER_SIZE 8
#define LOG_LINE_LEN 80
static char g_log_buffer[LOG_BUFFER_SIZE][LOG_LINE_LEN];
static int g_log_head = 0;
static int g_log_count = 0;

static void log_to_buffer(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_log_buffer[g_log_head], LOG_LINE_LEN, fmt, args);
    va_end(args);
    g_log_head = (g_log_head + 1) % LOG_BUFFER_SIZE;
    if (g_log_count < LOG_BUFFER_SIZE) g_log_count++;
}

/*==============================================================================
 * UTILITIES
 *============================================================================*/

static int64_t get_time_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (int64_t)((t - 116444736000000000ULL) / 10000);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

static void get_timestamp(char* buf, size_t len)
{
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    snprintf(buf, len, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void log_info(const char* fmt, ...)
{
    char ts[16];
    get_timestamp(ts, sizeof(ts));
    if (g_color) printf(C_GRAY "[%s]" C_RESET " ", ts);
    else printf("[%s] ", ts);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

static void format_hashrate(double hr, char* buf, size_t len)
{
    if (hr >= 1e12)      snprintf(buf, len, "%.2f TH/s", hr / 1e12);
    else if (hr >= 1e9)  snprintf(buf, len, "%.2f GH/s", hr / 1e9);
    else if (hr >= 1e6)  snprintf(buf, len, "%.2f MH/s", hr / 1e6);
    else if (hr >= 1e3)  snprintf(buf, len, "%.2f KH/s", hr / 1e3);
    else                 snprintf(buf, len, "%.0f H/s", hr);
}

static void format_time(int64_t ms, char* buf, size_t len)
{
    int64_t s = ms / 1000;
    int h = (int)(s / 3600);
    int m = (int)((s % 3600) / 60);
    int sec = (int)(s % 60);
    if (h > 0) snprintf(buf, len, "%dh %02dm", h, m);
    else if (m > 0) snprintf(buf, len, "%dm %02ds", m, sec);
    else snprintf(buf, len, "%ds", sec);
}

/*==============================================================================
 * POOL STATS HTTP CLIENT
 *============================================================================*/

/* Simple JSON value extractor (finds "key":value or "key":"value") */
static int json_get_int(const char* json, const char* key)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* p = strstr(json, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    while (*p == ' ') p++;
    return atoi(p);
}

static double json_get_double(const char* json, const char* key)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* p = strstr(json, pattern);
    if (!p) return 0.0;
    p += strlen(pattern);
    while (*p == ' ') p++;
    return atof(p);
}

static void json_get_string(const char* json, const char* key, char* out, size_t out_len)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char* p = strstr(json, pattern);
    if (!p) { out[0] = '\0'; return; }
    p += strlen(pattern);
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
}

/* Fetch pool stats from HTTP API (non-blocking) */
static void fetch_pool_stats(void)
{
    int64_t now = get_time_ms();
    if (now - g_pool_stats.last_update < POOL_STATS_INTERVAL) return;
    g_pool_stats.last_update = now;

    /* Connect to pool HTTP API on port 8080 */
    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) return;

    /* Set socket timeout */
#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    /* Resolve pool host */
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(g_stratum.host, "8080", &hints, &result) != 0) {
        close_socket(sock);
        return;
    }

    /* Connect */
    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        close_socket(sock);
        return;
    }
    freeaddrinfo(result);

    /* Send HTTP GET request */
    const char* request = "GET /api/stats HTTP/1.0\r\nHost: pool\r\nConnection: close\r\n\r\n";
    send(sock, request, (int)strlen(request), 0);

    /* Receive response */
    char response[4096] = {0};
    int total = 0;
    int n;
    while ((n = recv(sock, response + total, sizeof(response) - total - 1, 0)) > 0) {
        total += n;
        if (total >= (int)sizeof(response) - 1) break;
    }
    response[total] = '\0';
    close_socket(sock);

    /* Find JSON body (after \r\n\r\n) */
    const char* body = strstr(response, "\r\n\r\n");
    if (!body) return;
    body += 4;

    /* Parse JSON */
    g_pool_stats.miners_online = json_get_int(body, "online");
    g_pool_stats.pool_hashrate = json_get_double(body, "hashrate");
    json_get_string(body, "hashrateFormatted", g_pool_stats.pool_hashrate_str, sizeof(g_pool_stats.pool_hashrate_str));
    g_pool_stats.shares_accepted = (uint64_t)json_get_int(body, "accepted");
    g_pool_stats.shares_rejected = (uint64_t)json_get_int(body, "rejected");
    g_pool_stats.blocks_found = json_get_int(body, "found");
    g_pool_stats.valid = true;
}

/*==============================================================================
 * NETWORK
 *============================================================================*/

static bool net_init(void)
{
#ifdef _WIN32
    static bool init = false;
    if (!init) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        init = true;
    }
#endif
    return true;
}

static bool ip_exists(const char* ip)
{
    for (int i = 0; i < g_node_count; i++) {
        if (strcmp(g_nodes[i].ip, ip) == 0) return true;
    }
    return false;
}

/* Check if IP belongs to local machine */
static bool is_local_ip(const char* ip)
{
    /* Always skip localhost */
    if (strncmp(ip, "127.", 4) == 0) return true;

#ifdef _WIN32
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) return false;

    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) return false;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
        char local_ip[64];
        inet_ntop(AF_INET, &addr->sin_addr, local_ip, sizeof(local_ip));
        if (strcmp(ip, local_ip) == 0) {
            freeaddrinfo(result);
            return true;
        }
    }
    freeaddrinfo(result);
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return false;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        char local_ip[64];
        inet_ntop(AF_INET, &addr->sin_addr, local_ip, sizeof(local_ip));
        if (strcmp(ip, local_ip) == 0) {
            freeifaddrs(ifaddr);
            return true;
        }
    }
    freeifaddrs(ifaddr);
#endif
    return false;
}

/* Quick connectivity test (returns latency or 9999 if unreachable) */
static int quick_connect_test(const char* ip, uint16_t port)
{
    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) return 9999;

set_socket_nonblocking(sock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int64_t start = get_time_ms();
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    struct timeval tv = {1, 0};  /* 1 second timeout */
    int ret = select((int)sock + 1, NULL, &writefds, NULL, &tv);

close_socket(sock);

    if (ret > 0) {
        return (int)(get_time_ms() - start);
    }
    return 9999;
}

static void discover_nodes(void)
{
    g_node_count = 0;

    /* Use custom node if specified */
    if (g_custom_node[0]) {
        char host[256];
        uint16_t port = RPC_PORT;
        strncpy(host, g_custom_node, sizeof(host) - 1);

        /* Parse host:port */
        char* colon = strchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = (uint16_t)atoi(colon + 1);
        }

        strncpy(g_nodes[0].host, host, sizeof(g_nodes[0].host) - 1);
        strncpy(g_nodes[0].ip, host, sizeof(g_nodes[0].ip) - 1);
        g_nodes[0].port = port;
        g_nodes[0].latency_ms = 0;
        g_nodes[0].active = true;
        g_nodes[0].connected = true;
        g_nodes[0].height = 0;
        g_nodes[0].failures = 0;
        g_node_count = 1;
        return;
    }

    for (int i = 0; DNS_SEEDS[i] != NULL && g_node_count < MAX_NODES; i++) {
        struct addrinfo hints, *result, *rp;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(DNS_SEEDS[i], NULL, &hints, &result) != 0) continue;

        for (rp = result; rp != NULL && g_node_count < MAX_NODES; rp = rp->ai_next) {
            struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
            char ip[64];
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

            if (ip_exists(ip)) continue;
            if (is_local_ip(ip)) continue;  /* Skip local interface IPs */

            /* Test connectivity - skip unreachable nodes (including own external IP behind NAT) */
            int latency = quick_connect_test(ip, RPC_PORT);
            if (latency >= 5000) continue;  /* Skip if can't connect in 5s */

            strncpy(g_nodes[g_node_count].host, DNS_SEEDS[i], sizeof(g_nodes[g_node_count].host) - 1);
            strncpy(g_nodes[g_node_count].ip, ip, sizeof(g_nodes[g_node_count].ip) - 1);
            g_nodes[g_node_count].port = RPC_PORT;
            g_nodes[g_node_count].latency_ms = latency;
            g_nodes[g_node_count].active = true;
            g_nodes[g_node_count].connected = true;
            g_nodes[g_node_count].height = 0;
            g_nodes[g_node_count].failures = 0;
            g_node_count++;
        }
        freeaddrinfo(result);
    }
}

static int measure_latency(const char* host, uint16_t port)
{
    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) return 9999;

set_socket_nonblocking(sock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, host, &addr.sin_addr);
    addr.sin_port = htons(port);

    int64_t start = get_time_ms();

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0 && !socket_would_block()) {
        close_socket(sock);
        return 9999;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = {2, 0};

    ret = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (ret <= 0) {
close_socket(sock);
        return 9999;
    }

    int64_t elapsed = get_time_ms() - start;

close_socket(sock);

    return (int)elapsed;
}

static void update_node_latencies(void)
{
    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].active) {
            g_nodes[i].latency_ms = measure_latency(g_nodes[i].ip, g_nodes[i].port);
            g_nodes[i].connected = (g_nodes[i].latency_ms < 5000);
        }
    }
}

static int select_best_node(void)
{
    int best = -1;
    int best_latency = 99999;

    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].active && g_nodes[i].connected && g_nodes[i].latency_ms < best_latency) {
            best_latency = g_nodes[i].latency_ms;
            best = i;
        }
    }

    return best;
}

/*==============================================================================
 * STRATUM CLIENT FUNCTIONS
 *============================================================================*/

static void hex_to_bytes(const char* hex, uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static bool stratum_connect(stratum_ctx_t* ctx)
{
    ctx->sock = create_tcp_socket();
    if (ctx->sock == MINER_INVALID_SOCKET) return false;

    /* Set timeout */
#ifdef _WIN32
    DWORD timeout = 10000;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {10, 0};
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);

    /* Resolve hostname */
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ctx->host, NULL, &hints, &result) != 0) {
        close_socket(ctx->sock);
        ctx->sock = MINER_INVALID_SOCKET;
        return false;
    }

    addr.sin_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr;
    freeaddrinfo(result);

    /* Measure connection latency */
    int64_t t_start = get_time_ms();
    if (connect(ctx->sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close_socket(ctx->sock);
        ctx->sock = MINER_INVALID_SOCKET;
        return false;
    }
    ctx->latency_ms = (int)(get_time_ms() - t_start);

    ctx->connected = true;
    ctx->recv_len = 0;
    ctx->msg_id = 1;
    ctx->connect_time = time(NULL);
    ctx->jobs_received = 0;
    return true;
}

static void stratum_disconnect(stratum_ctx_t* ctx)
{
    if (ctx->sock != MINER_INVALID_SOCKET) {
        close_socket(ctx->sock);
        ctx->sock = MINER_INVALID_SOCKET;
        if (ctx->connected) {
            log_to_buffer("Disconnected from pool");
        }
    }
    ctx->connected = false;
    ctx->authorized = false;
    ctx->subscribed = false;
    ctx->has_job = false;
}

static bool stratum_send(stratum_ctx_t* ctx, const char* msg)
{
    if (!ctx->connected) return false;

    size_t len = strlen(msg);
    char* buf = (char*)malloc(len + 2);
    if (!buf) return false;

    memcpy(buf, msg, len);
    buf[len] = '\n';
    buf[len + 1] = '\0';

    int sent = send(ctx->sock, buf, (int)(len + 1), 0);
    free(buf);

    return sent == (int)(len + 1);
}

static bool stratum_recv_line(stratum_ctx_t* ctx, char* line, size_t line_size)
{
    /* Check if we have a complete line in buffer */
    while (1) {
        char* newline = (char*)memchr(ctx->recv_buf, '\n', ctx->recv_len);
        if (newline) {
            size_t line_len = newline - ctx->recv_buf;
            if (line_len >= line_size) line_len = line_size - 1;
            memcpy(line, ctx->recv_buf, line_len);
            line[line_len] = '\0';

            /* Remove line from buffer */
            int remaining = ctx->recv_len - (int)(newline - ctx->recv_buf) - 1;
            if (remaining > 0) {
                memmove(ctx->recv_buf, newline + 1, remaining);
            }
            ctx->recv_len = remaining;
            return true;
        }

        /* Need more data */
        if (ctx->recv_len >= (int)sizeof(ctx->recv_buf) - 1) {
            /* Buffer full, no newline - error */
            return false;
        }

        int n = recv(ctx->sock, ctx->recv_buf + ctx->recv_len,
                     (int)sizeof(ctx->recv_buf) - ctx->recv_len - 1, 0);
        if (n <= 0) return false;
        ctx->recv_len += n;
    }
}

static bool stratum_subscribe(stratum_ctx_t* ctx)
{
    char msg[256];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.subscribe\",\"params\":[\"%s/%s\"]}",
        ctx->msg_id++, MINER_NAME, MINER_VERSION);

    if (!stratum_send(ctx, msg)) return false;

    /* Read response */
    char line[4096];
    if (!stratum_recv_line(ctx, line, sizeof(line))) return false;

    /* Parse response - look for extranonce1 and extranonce2_size */
    char* result = strstr(line, "\"result\":");
    if (!result) return false;

    /* Find extranonce1 (first string in result array after subscription details) */
    char* en1_start = strstr(result, "\",\"");
    if (en1_start) {
        en1_start += 3;
        char* en1_end = strchr(en1_start, '"');
        if (en1_end) {
            size_t en1_len = en1_end - en1_start;
            if (en1_len < sizeof(ctx->extranonce1)) {
                memcpy(ctx->extranonce1, en1_start, en1_len);
                ctx->extranonce1[en1_len] = '\0';
            }
        }
    }

    /* Find extranonce2_size (last number in result array) */
    char* last_num = strrchr(result, ',');
    if (last_num) {
        ctx->extranonce2_size = atoi(last_num + 1);
        if (ctx->extranonce2_size <= 0 || ctx->extranonce2_size > 8) {
            ctx->extranonce2_size = 4;  /* Default */
        }
    }

    ctx->subscribed = true;
    return true;
}

static bool stratum_authorize(stratum_ctx_t* ctx)
{
    char msg[512];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}",
        ctx->msg_id++, ctx->worker, ctx->password);

    if (!stratum_send(ctx, msg)) return false;

    /* Read response */
    char line[4096];
    if (!stratum_recv_line(ctx, line, sizeof(line))) return false;

    /* Check for success */
    if (strstr(line, "\"result\":true")) {
        ctx->authorized = true;
        log_to_buffer("Connected to pool %s:%d", ctx->host, ctx->port);
        return true;
    }

    return false;
}

static bool stratum_parse_notify(stratum_ctx_t* ctx, const char* line)
{
    /* Parse mining.notify message
     * params: [job_id, prevhash, coinb1, coinb2, merkle_branches[], version, nbits, ntime, clean]
     */
    char* params = strstr(line, "\"params\":");
    if (!params) return false;

    params = strchr(params, '[');
    if (!params) return false;
    params++;

    /* Extract job_id */
    char* p = strchr(params, '"');
    if (!p) return false;
    p++;
    char* end = strchr(p, '"');
    if (!end) return false;
    size_t len = end - p;
    if (len >= sizeof(ctx->job_id)) len = sizeof(ctx->job_id) - 1;
    memcpy(ctx->job_id, p, len);
    ctx->job_id[len] = '\0';

    /* Extract prevhash */
    p = strchr(end + 1, '"');
    if (!p) return false;
    p++;
    end = strchr(p, '"');
    if (!end) return false;
    len = end - p;
    if (len >= 64) {
        hex_to_bytes(p, ctx->prevhash, 32);
    }

    /* Extract coinb1 */
    p = strchr(end + 1, '"');
    if (!p) return false;
    p++;
    end = strchr(p, '"');
    if (!end) return false;
    len = end - p;
    ctx->coinb1_len = len / 2;
    if (ctx->coinb1_len > sizeof(ctx->coinb1)) ctx->coinb1_len = sizeof(ctx->coinb1);
    hex_to_bytes(p, ctx->coinb1, ctx->coinb1_len);

    /* Extract coinb2 */
    p = strchr(end + 1, '"');
    if (!p) return false;
    p++;
    end = strchr(p, '"');
    if (!end) return false;
    len = end - p;
    ctx->coinb2_len = len / 2;
    if (ctx->coinb2_len > sizeof(ctx->coinb2)) ctx->coinb2_len = sizeof(ctx->coinb2);
    hex_to_bytes(p, ctx->coinb2, ctx->coinb2_len);

    /* Skip merkle branches array */
    p = strchr(end + 1, ']');
    if (!p) return false;

    /* Extract version (skip for now, FTC uses fixed) */

    /* Find version, nbits and ntime - they're the hex values near the end */
    char* comma = p;
    int field_count = 0;
    while (comma && field_count < 3) {
        comma = strchr(comma + 1, '"');
        if (comma) {
            comma++;
            char* field_end = strchr(comma, '"');
            if (field_end) {
                char field[32] = {0};
                size_t flen = field_end - comma;
                if (flen < sizeof(field)) {
                    memcpy(field, comma, flen);
                    if (field_count == 0) {
                        /* version */
                        ctx->version = (uint32_t)strtoul(field, NULL, 16);
                    } else if (field_count == 1) {
                        /* nbits */
                        ctx->nbits = (uint32_t)strtoul(field, NULL, 16);
                    } else if (field_count == 2) {
                        /* ntime */
                        ctx->ntime = (uint32_t)strtoul(field, NULL, 16);
                    }
                }
                comma = field_end;
            }
            field_count++;
        }
    }

    ctx->has_job = true;
    ctx->jobs_received++;
    log_to_buffer("New job #%llu", (unsigned long long)ctx->jobs_received);
    return true;
}

static bool stratum_parse_difficulty(stratum_ctx_t* ctx, const char* line)
{
    char* params = strstr(line, "\"params\":");
    if (!params) return false;

    params = strchr(params, '[');
    if (!params) return false;

    double new_diff = atof(params + 1);
    if (new_diff <= 0) new_diff = 1.0;
    ctx->target_diff = new_diff;
    return true;
}

static void stratum_handle_message(stratum_ctx_t* ctx, const char* line)
{
    if (strstr(line, "mining.notify")) {
        stratum_parse_notify(ctx, line);
    } else if (strstr(line, "mining.set_difficulty")) {
        stratum_parse_difficulty(ctx, line);
    } else if (strstr(line, "\"result\":true") && strstr(line, "\"id\":")) {
        /* Share accepted */
        ctx->shares_accepted++;
        ctx->last_share_time = time(NULL);
        log_to_buffer("ACCEPTED share #%llu (%.1f%% rate)",
                  (unsigned long long)ctx->shares_accepted,
                  ctx->shares_sent > 0 ? (100.0 * ctx->shares_accepted / ctx->shares_sent) : 0.0);
    } else if (strstr(line, "\"result\":null") || strstr(line, "\"error\":")) {
        /* Share rejected or error */
        if (ctx->shares_sent > ctx->shares_accepted + ctx->shares_rejected + ctx->shares_stale) {
            if (strstr(line, "stale") || strstr(line, "Stale") || strstr(line, "job not found")) {
                ctx->shares_stale++;
                log_to_buffer("STALE share #%llu", (unsigned long long)ctx->shares_stale);
            } else {
                ctx->shares_rejected++;
                log_to_buffer("REJECTED share #%llu", (unsigned long long)ctx->shares_rejected);
            }
        }
    }
}

static bool stratum_poll(stratum_ctx_t* ctx)
{
    if (!ctx->connected) return false;

    /* Set non-blocking for poll */
    set_socket_nonblocking(ctx->sock);

    char line[4096];
    bool got_message = false;

    while (1) {
        /* Try to get data without blocking */
        int n = recv(ctx->sock, ctx->recv_buf + ctx->recv_len,
                     (int)sizeof(ctx->recv_buf) - ctx->recv_len - 1, 0);

        if (n > 0) {
            ctx->recv_len += n;
        } else if (n == 0) {
            /* Connection closed */
            stratum_disconnect(ctx);
            return false;
        }

        /* Check for complete line */
        char* newline = (char*)memchr(ctx->recv_buf, '\n', ctx->recv_len);
        if (newline) {
            size_t line_len = newline - ctx->recv_buf;
            if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
            memcpy(line, ctx->recv_buf, line_len);
            line[line_len] = '\0';

            /* Remove from buffer */
            int remaining = ctx->recv_len - (int)(newline - ctx->recv_buf) - 1;
            if (remaining > 0) {
                memmove(ctx->recv_buf, newline + 1, remaining);
            }
            ctx->recv_len = remaining;

            stratum_handle_message(ctx, line);
            got_message = true;
        } else {
            break;
        }
    }

    /* Restore blocking mode */
#ifdef _WIN32
    u_long mode = 0;
    ioctlsocket(ctx->sock, FIONBIO, &mode);
#else
    int flags = fcntl(ctx->sock, F_GETFL, 0);
    fcntl(ctx->sock, F_SETFL, flags & ~O_NONBLOCK);
#endif

    return got_message || ctx->has_job;
}

static bool stratum_submit_share(stratum_ctx_t* ctx, uint32_t nonce, uint32_t ntime)
{
    char extranonce2_hex[32];
    for (int i = 0; i < ctx->extranonce2_size; i++) {
        sprintf(extranonce2_hex + i * 2, "%02x",
                (unsigned int)((ctx->extranonce2 >> (i * 8)) & 0xff));
    }

    char ntime_hex[16], nonce_hex[16];
    sprintf(ntime_hex, "%08x", ntime);
    sprintf(nonce_hex, "%08x", nonce);

    char msg[512];
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}",
        ctx->msg_id++, ctx->worker, ctx->job_id, extranonce2_hex, ntime_hex, nonce_hex);

    ctx->shares_sent++;
    return stratum_send(ctx, msg);
}

/*==============================================================================
 * RPC CLIENT
 *============================================================================*/

static char* rpc_call(int node_idx, const char* method, const char* params)
{
    if (node_idx < 0 || node_idx >= g_node_count) return NULL;

    node_info_t* node = &g_nodes[node_idx];

    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) return NULL;

#ifdef _WIN32
    DWORD timeout = 3000;  /* 3 second timeout - more tolerant */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {3, 0};  /* 3 second timeout */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, node->ip, &addr.sin_addr);
    addr.sin_port = htons(node->port);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
close_socket(sock);
        node->failures++;
        return NULL;
    }

    char request[4096];
    int req_len = snprintf(request, sizeof(request),
        "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":1}",
        method, params ? params : "[]");

    char http[8192];
    int http_len = snprintf(http, sizeof(http),
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        node->ip, node->port, req_len, request);

    send(sock, http, http_len, 0);

    char* response = (char*)malloc(65536);
    if (!response) {
close_socket(sock);
        return NULL;
    }

    int total = 0;
    while (total < 65535) {
        int ret = recv(sock, response + total, 65535 - total, 0);
        if (ret <= 0) break;
        total += ret;
        response[total] = '\0';
        char* body = strstr(response, "\r\n\r\n");
        if (body && strrchr(body, '}')) break;
    }
    response[total] = '\0';

close_socket(sock);

    /* Check for valid response */
    if (total == 0) {
        free(response);
        node->failures++;
        return NULL;
    }

    char* body = strstr(response, "\r\n\r\n");
    if (!body) {
        free(response);
        node->failures++;
        return NULL;
    }

    body += 4;
    if (strlen(body) == 0 || !strchr(body, '{')) {
        free(response);
        node->failures++;
        return NULL;
    }

    memmove(response, body, strlen(body) + 1);
    node->failures = 0;
    return response;
}

/*==============================================================================
 * MINING API
 *============================================================================*/

static bool get_node_info(int node_idx)
{
    char* response = rpc_call(node_idx, "getinfo", "[]");
    if (!response) return false;

    char* h = strstr(response, "\"blocks\":");
    if (h) g_current_height = (uint32_t)atoi(h + 9);

    char* p = strstr(response, "\"connections\":");
    if (p) g_peer_count = atoi(p + 14);

    char* d = strstr(response, "\"difficulty\":");
    if (d) g_difficulty = atof(d + 13);

    g_nodes[node_idx].height = g_current_height;
    free(response);
    return true;
}

static ftc_block_t* get_block_template(int node_idx, uint32_t* out_height)
{
    char params[256];
    snprintf(params, sizeof(params), "[\"%s\"]", g_miner_address);

    char* response = rpc_call(node_idx, "getblocktemplate", params);
    if (!response) return NULL;

    char* height_str = strstr(response, "\"height\":");
    if (height_str && out_height) {
        *out_height = (uint32_t)atoi(height_str + 9);
    }

    char* blockdata_start = strstr(response, "\"blockdata\":\"");
    if (!blockdata_start) {
        free(response);
        return NULL;
    }
    blockdata_start += 13;

    char* blockdata_end = strchr(blockdata_start, '"');
    if (!blockdata_end) {
        free(response);
        return NULL;
    }

    size_t hex_len = blockdata_end - blockdata_start;
    size_t data_len = hex_len / 2;

    uint8_t* block_data = (uint8_t*)malloc(data_len);
    if (!block_data) {
        free(response);
        return NULL;
    }

    for (size_t i = 0; i < data_len; i++) {
        unsigned int byte;
        sscanf(blockdata_start + i * 2, "%02x", &byte);
        block_data[i] = (uint8_t)byte;
    }

    ftc_block_t* block = ftc_block_deserialize(block_data, data_len);
    free(block_data);
    free(response);
    return block;
}

/* Fire-and-forget submit - don't wait for response to maximize GPU utilization */
static void submit_block_async(int node_idx, ftc_block_t* block)
{
    if (node_idx < 0 || node_idx >= g_node_count) return;

    node_info_t* node = &g_nodes[node_idx];

    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return;

    ftc_block_serialize(block, data, size);

    char* hex = (char*)malloc(size * 2 + 1);
    if (!hex) {
        free(data);
        return;
    }

bytes_to_hex(data, size, hex);
    free(data);

    /* Build JSON-RPC request */
    char* request = (char*)malloc(size * 2 + 256);
    if (!request) {
        free(hex);
        return;
    }

    int req_len = sprintf(request,
        "{\"jsonrpc\":\"2.0\",\"method\":\"submitblock\",\"params\":[\"%s\"],\"id\":1}",
        hex);
    free(hex);

    /* Open socket */
    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) {
        free(request);
        return;
    }

    /* Very short timeout - just enough to send */
#ifdef _WIN32
    DWORD timeout = 500;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {0, 500000};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, node->ip, &addr.sin_addr);
    addr.sin_port = htons(node->port);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char http[256];
        int http_len = sprintf(http,
            "POST / HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n",
            node->ip, node->port, req_len);

        send(sock, http, http_len, 0);
        send(sock, request, req_len, 0);
        /* Don't wait for response - just close and continue mining */
    }

close_socket(sock);
    free(request);
}

static bool submit_block(int node_idx, ftc_block_t* block)
{
    if (node_idx < 0 || node_idx >= g_node_count) return false;

    node_info_t* node = &g_nodes[node_idx];

    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return false;

    ftc_block_serialize(block, data, size);

    char* hex = (char*)malloc(size * 2 + 1);
    if (!hex) {
        free(data);
        return false;
    }

bytes_to_hex(data, size, hex);
    free(data);

    /* Build JSON-RPC request */
    char* request = (char*)malloc(size * 2 + 256);
    if (!request) {
        free(hex);
        return false;
    }

    int req_len = sprintf(request,
        "{\"jsonrpc\":\"2.0\",\"method\":\"submitblock\",\"params\":[\"%s\"],\"id\":1}",
        hex);
    free(hex);

    /* Open socket */
    miner_socket_t sock = create_tcp_socket();
    if (sock == MINER_INVALID_SOCKET) {
        free(request);
        return false;
    }

    /* Set timeouts - short to minimize GPU idle time */
#ifdef _WIN32
    DWORD timeout = 1000;  /* 1 second */
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {1, 0};  /* 1 second */
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, node->ip, &addr.sin_addr);
    addr.sin_port = htons(node->port);

    bool accepted = false;

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char http[256];
        int http_len = sprintf(http,
            "POST / HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n",
            node->ip, node->port, req_len);

        send(sock, http, http_len, 0);
        send(sock, request, req_len, 0);

        /* Wait for response and check if accepted */
        char response[4096];
        int total = 0;
        while (total < (int)sizeof(response) - 1) {
            int n = recv(sock, response + total, sizeof(response) - 1 - total, 0);
            if (n <= 0) break;
            total += n;
        }
        response[total] = '\0';

        /* Check response - accepted if "result":null (no error) */
        if (total > 0) {
            /* Block accepted if response contains "result":null and no "error" field with message */
            if (strstr(response, "\"result\":null") != NULL &&
                strstr(response, "\"error\":{") == NULL) {
                accepted = true;
            }
        }
    }

close_socket(sock);
    free(request);
    return accepted;
}

/*==============================================================================
 * RIGEL-STYLE DISPLAY
 *============================================================================*/

/* Per-GPU stats */
typedef struct {
    double hashrate;
    double hashrate_avg;
    int power_w;
    int temp_core;
    int temp_mem;
    int fan_pct;
    int clock_core;
    int clock_mem;
} gpu_stats_t;

static gpu_stats_t g_gpu_stats[FTC_GPU_MAX_DEVICES] = {0};
static double g_gpu_hashrates[FTC_GPU_MAX_DEVICES] = {0};
static int g_display_line = 0;

static void format_uptime(int64_t ms, char* buf, size_t len)
{
    int64_t sec = ms / 1000;
    int d = (int)(sec / 86400);
    int h = (int)((sec % 86400) / 3600);
    int m = (int)((sec % 3600) / 60);
    int s = (int)(sec % 60);
    if (d > 0) snprintf(buf, len, "%dd %02d:%02d:%02d", d, h, m, s);
    else snprintf(buf, len, "%02d:%02d:%02d", h, m, s);
}

static void print_header_rigel(void)
{
    int64_t uptime = get_time_ms() - g_start_time;
    char uptime_str[32];
    format_uptime(uptime, uptime_str, sizeof(uptime_str));

    /* Line 1: Title bar */
    printf(C_CYAN "%s v%s" C_RESET " - [Windows]", MINER_NAME, MINER_VERSION);
    printf("%60s" C_YELLOW "Uptime" C_RESET "\n", "");
    printf("Algorithm: " C_WHITE "keccak256" C_RESET "                                                     %s\n", uptime_str);
    printf("\n");

    /* Line 2: Pool header */
    printf(C_BG_GREEN C_BLACK "Pool" C_RESET "\n");
    printf(C_BG_GREEN C_BLACK "%-12s %-8s %-10s %-6s %-40s" C_RESET "\n",
           "Algorithm", "Latency", "Diff", "SSL", "Node");

    /* Pool info */
    printf("%-12s " C_CYAN "%-8d" C_RESET " %-10.2f %-6s %s\n",
           "keccak256",
           g_nodes[g_active_node].latency_ms,
           g_difficulty,
           "no",
           g_nodes[g_active_node].ip);
    printf("\n");
}

static void print_gpu_table_header(void)
{
    printf(C_BG_BLUE C_WHITE " # GPU                        Hashrate/Avg        A/S/Hw " C_RESET "\n");
}

static void print_gpu_row(int idx, const ftc_gpu_device_t* dev, gpu_stats_t* stats)
{
    char hr_str[16], hr_avg_str[16];
    format_hashrate(stats->hashrate, hr_str, sizeof(hr_str));
    format_hashrate(stats->hashrate_avg, hr_avg_str, sizeof(hr_avg_str));

    printf(" %d %-25s " C_GREEN "%-8s" C_RESET "/" C_YELLOW "%-8s" C_RESET " "
           C_GREEN "%3llu" C_RESET "/" C_RED "%3d" C_RESET "/" C_YELLOW "%3d" C_RESET "\n",
           idx, dev->name, hr_str, hr_avg_str,
           (unsigned long long)g_blocks_accepted, 0, 0);
}

/* Static display that updates in-place */
static void draw_static_display(void)
{
    int gpu_count = ftc_gpu_farm_device_count(g_farm);

    /* Fetch pool stats periodically */
    if (g_mining_mode == MINING_MODE_POOL && g_stratum.connected) {
        fetch_pool_stats();
    }

    /* Update GPU hashrates */
    for (int i = 0; i < gpu_count; i++) {
        g_gpu_hashrates[i] = ftc_gpu_farm_get_device_hashrate(g_farm, i);
    }

    double total_hr = ftc_gpu_farm_get_hashrate(g_farm);
    char hr_str[32], uptime_str[32];
    format_hashrate(total_hr, hr_str, sizeof(hr_str));
    format_uptime(get_time_ms() - g_start_time, uptime_str, sizeof(uptime_str));

    /* Move cursor to home and redraw */
    printf(C_HOME C_HIDE_CUR);

    /* Header */
    printf(C_CLR_LINE C_CYAN C_BOLD "FTC GPU Miner v%s" C_RESET "  |  " C_WHITE "keccak256" C_RESET "\n", MINER_VERSION);
    printf(C_CLR_LINE "================================================================================\n");

    /* Node/Pool info */
    if (g_mining_mode == MINING_MODE_POOL) {
        uint64_t total_shares = g_stratum.shares_accepted + g_stratum.shares_rejected + g_stratum.shares_stale;
        double accept_rate = total_shares > 0 ? (100.0 * g_stratum.shares_accepted / total_shares) : 0.0;

        printf(C_CLR_LINE "Pool: " C_MAGENTA "%s:%d" C_RESET "  Latency: " C_GREEN "%dms" C_RESET "  Diff: " C_YELLOW "%.1f" C_RESET "  Jobs: " C_CYAN "%llu" C_RESET "\n",
               g_stratum.host, g_stratum.port, g_stratum.latency_ms, g_difficulty,
               (unsigned long long)g_stratum.jobs_received);
        printf(C_CLR_LINE "Shares: " C_GREEN "%llu" C_RESET "/" C_RED "%llu" C_RESET "/" C_YELLOW "%llu" C_RESET " (A/R/S)  Rate: " C_GREEN "%.1f%%" C_RESET "\n",
               (unsigned long long)g_stratum.shares_accepted,
               (unsigned long long)g_stratum.shares_rejected,
               (unsigned long long)g_stratum.shares_stale,
               accept_rate);

        /* Pool stats from HTTP API */
        if (g_pool_stats.valid) {
            printf(C_CLR_LINE "Online: " C_CYAN "%d" C_RESET " miners  Pool HR: " C_GREEN "%s" C_RESET "  Blocks: " C_YELLOW "%d" C_RESET "\n",
                   g_pool_stats.miners_online,
                   g_pool_stats.pool_hashrate_str[0] ? g_pool_stats.pool_hashrate_str : "0 H/s",
                   g_pool_stats.blocks_found);
        }
    } else {
        printf(C_CLR_LINE "Node: " C_CYAN "%s" C_RESET "  Latency: " C_GREEN "%dms" C_RESET "  Height: " C_YELLOW "%u" C_RESET "  Diff: %.4f\n",
               g_nodes[g_active_node].ip,
               g_nodes[g_active_node].latency_ms,
               g_current_height,
               g_difficulty);
    }
    printf(C_CLR_LINE "================================================================================\n");

    /* GPU table header */
    printf(C_CLR_LINE C_BOLD " GPU  %-24s  %-12s  %-12s  Blocks" C_RESET "\n", "Device", "Hashrate", "Avg");
    printf(C_CLR_LINE "--------------------------------------------------------------------------------\n");

    /* GPU rows */
    for (int i = 0; i < gpu_count; i++) {
        const ftc_gpu_device_t* dev = ftc_gpu_farm_get_device(g_farm, i);
        if (!dev) continue;

        char gpu_hr[16], gpu_avg[16];
        format_hashrate(g_gpu_hashrates[i], gpu_hr, sizeof(gpu_hr));
        format_hashrate(g_gpu_hashrates[i], gpu_avg, sizeof(gpu_avg));  /* TODO: rolling average */

        printf(C_CLR_LINE " [%d]  " C_WHITE "%-24s" C_RESET "  " C_GREEN "%-12s" C_RESET "  " C_YELLOW "%-12s" C_RESET "  %llu\n",
               i, dev->name, gpu_hr, gpu_avg, (unsigned long long)g_blocks_accepted);
    }

    printf(C_CLR_LINE "--------------------------------------------------------------------------------\n");

    /* Total row */
    printf(C_CLR_LINE C_BOLD " SUM  %-24s  " C_GREEN "%-12s" C_RESET C_BOLD "  %-12s  " C_GREEN "%llu" C_RESET "/" C_YELLOW "%llu" C_RESET "\n",
           "", hr_str, hr_str,
           (unsigned long long)g_blocks_accepted,
           (unsigned long long)g_blocks_found);

    printf(C_CLR_LINE "================================================================================\n");

    /* Status line */
    if (g_mining_mode == MINING_MODE_POOL) {
        char conn_uptime[32];
        char last_share_str[32];
        time_t now = time(NULL);

        if (g_stratum.connect_time > 0) {
            format_uptime((now - g_stratum.connect_time) * 1000, conn_uptime, sizeof(conn_uptime));
        } else {
            snprintf(conn_uptime, sizeof(conn_uptime), "N/A");
        }

        if (g_stratum.last_share_time > 0) {
            int secs = (int)(now - g_stratum.last_share_time);
            if (secs < 60) {
                snprintf(last_share_str, sizeof(last_share_str), "%ds ago", secs);
            } else if (secs < 3600) {
                snprintf(last_share_str, sizeof(last_share_str), "%dm %ds ago", secs / 60, secs % 60);
            } else {
                snprintf(last_share_str, sizeof(last_share_str), "%dh %dm ago", secs / 3600, (secs % 3600) / 60);
            }
        } else {
            snprintf(last_share_str, sizeof(last_share_str), "None");
        }

        printf(C_CLR_LINE "Uptime: " C_CYAN "%s" C_RESET "  Connected: " C_GREEN "%s" C_RESET "  Last share: " C_YELLOW "%s" C_RESET "\n",
               uptime_str, conn_uptime, last_share_str);
        printf(C_CLR_LINE "Hashes: " C_WHITE "%.2f B" C_RESET "  Sent: " C_CYAN "%llu" C_RESET "\n",
               (double)g_total_hashes / 1e9, (unsigned long long)g_stratum.shares_sent);
    } else {
        printf(C_CLR_LINE "Uptime: " C_CYAN "%s" C_RESET "  Total hashes: " C_WHITE "%.2f B" C_RESET "\n",
               uptime_str, (double)g_total_hashes / 1e9);
    }

    printf(C_CLR_LINE "================================================================================\n");

    /* Log buffer - show recent events */
    printf(C_CLR_LINE C_BOLD "Recent:" C_RESET "\n");
    for (int i = 0; i < LOG_BUFFER_SIZE; i++) {
        int idx = (g_log_head - g_log_count + i + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;
        if (i < g_log_count) {
            if (strstr(g_log_buffer[idx], "BLOCK!") || strstr(g_log_buffer[idx], "ACCEPTED")) {
                printf(C_CLR_LINE C_GREEN " %s" C_RESET "\n", g_log_buffer[idx]);
            } else if (strstr(g_log_buffer[idx], "NETWORK") || strstr(g_log_buffer[idx], "Connected")) {
                printf(C_CLR_LINE C_CYAN " %s" C_RESET "\n", g_log_buffer[idx]);
            } else if (strstr(g_log_buffer[idx], "REJECTED")) {
                printf(C_CLR_LINE C_RED " %s" C_RESET "\n", g_log_buffer[idx]);
            } else if (strstr(g_log_buffer[idx], "STALE")) {
                printf(C_CLR_LINE C_YELLOW " %s" C_RESET "\n", g_log_buffer[idx]);
            } else {
                printf(C_CLR_LINE " %s\n", g_log_buffer[idx]);
            }
        } else {
            printf(C_CLR_LINE "\n");
        }
    }

    printf(C_CLR_LINE "\n");
    printf(C_SHOW_CUR);
    fflush(stdout);
}

static void log_stats(void)
{
    double total_hr = ftc_gpu_farm_get_hashrate(g_farm);
    char hr_str[32];
    format_hashrate(total_hr, hr_str, sizeof(hr_str));

    char uptime_str[32];
    format_uptime(get_time_ms() - g_start_time, uptime_str, sizeof(uptime_str));

    log_info(C_GREEN "%s" C_RESET " | height %u | diff %.2f | blocks %llu/%llu | up %s\n",
             hr_str, g_current_height, g_difficulty,
             (unsigned long long)g_blocks_accepted,
             (unsigned long long)g_blocks_found,
             uptime_str);
}

static void print_gpu_hashrate_bar(int idx, double hashrate)
{
    char hr_str[16];
    format_hashrate(hashrate, hr_str, sizeof(hr_str));

    char ts[32];
    get_timestamp(ts, sizeof(ts));

    /* Progress bar */
    int bar_width = 40;
    double max_hr = 10e12;  /* 10 TH/s max for display */
    int filled = (int)((hashrate / max_hr) * bar_width);
    if (filled > bar_width) filled = bar_width;
    if (filled < 0) filled = 0;

    printf("[%s] |%d|GPU #%d|", ts, idx, idx);

    /* Bar */
    printf(C_GREEN);
    for (int i = 0; i < filled; i++) printf("+");
    printf(C_RESET);
    for (int i = filled; i < bar_width; i++) printf("-");

    printf("|%10s|", hr_str);

    /* Shares */
    printf(" %3llu| %2d| %2d|\n",
           (unsigned long long)g_blocks_accepted, 0, 0);
}

static void print_total_hashrate(void)
{
    double total = ftc_gpu_farm_get_hashrate(g_farm);
    char hr_str[16];
    format_hashrate(total, hr_str, sizeof(hr_str));

    char ts[32];
    get_timestamp(ts, sizeof(ts));

    printf("[%s]                  Total: " C_GREEN "-|%s" C_RESET "| %3llu| %2d| %2d|\n",
           ts, hr_str,
           (unsigned long long)g_blocks_accepted, 0, 0);
}

static void print_separator(void)
{
    char ts[32];
    get_timestamp(ts, sizeof(ts));
    printf("[%s] +==============================================================================+\n", ts);
}

static void draw_display(void)
{
    printf(C_CLEAR C_HOME);  /* Clear screen, go home */
    print_header_rigel();
    print_gpu_table_header();

    int gpu_count = ftc_gpu_farm_device_count(g_farm);
    for (int i = 0; i < gpu_count; i++) {
        const ftc_gpu_device_t* dev = ftc_gpu_farm_get_device(g_farm, i);
        if (dev) {
            g_gpu_stats[i].hashrate = g_gpu_hashrates[i];
            g_gpu_stats[i].hashrate_avg = g_gpu_hashrates[i];  /* TODO: actual average */
            print_gpu_row(i, dev, &g_gpu_stats[i]);
        }
    }

    /* Total row */
    double total = ftc_gpu_farm_get_hashrate(g_farm);
    char hr_str[16], hr_avg_str[16];
    format_hashrate(total, hr_str, sizeof(hr_str));
    format_hashrate(total, hr_avg_str, sizeof(hr_avg_str));
    printf("  " C_BOLD "%-27s " C_GREEN "%-8s" C_RESET "/" C_YELLOW "%-8s" C_RESET " "
           C_GREEN "%3llu" C_RESET "/" C_RED "%3d" C_RESET "/" C_YELLOW "%3d" C_RESET "\n",
           "Total:", hr_str, hr_avg_str,
           (unsigned long long)g_blocks_accepted, 0, 0);

    printf("\n");

    /* Per-GPU hashrate bars */
    for (int i = 0; i < gpu_count; i++) {
        print_gpu_hashrate_bar(i, g_gpu_hashrates[i]);
    }
    print_total_hashrate();
    print_separator();

    fflush(stdout);
}

static void log_share_found(uint32_t height, const char* hash, bool accepted)
{
    char ts[32];
    get_timestamp(ts, sizeof(ts));

    if (accepted) {
        log_to_buffer("[%s] BLOCK! h=%u %s", ts, height, hash);
    }
    /* Don't show rejected blocks - only accepted ones matter */
}

static void print_final_stats(void)
{
    int64_t elapsed = get_time_ms() - g_start_time;
    double hashrate = elapsed > 0 ? (double)g_total_hashes * 1000.0 / elapsed : 0;

    char hr_str[32], time_str[32];
    format_hashrate(hashrate, hr_str, sizeof(hr_str));
    format_time(elapsed, time_str, sizeof(time_str));

    printf("\n");
    printf(C_CYAN "== Session Summary ==" C_RESET "\n");
    printf("Duration:    %s\n", time_str);
    printf("Avg Speed:   %s\n", hr_str);
    printf("GPUs:        %d\n", ftc_gpu_farm_device_count(g_farm));
    printf("Blocks:      %llu found, %llu accepted",
           (unsigned long long)g_blocks_found,
           (unsigned long long)g_blocks_accepted);

    if (g_blocks_found > 0) {
        double rate = (double)g_blocks_accepted / g_blocks_found * 100.0;
        printf(" (%.0f%%)", rate);
    }
    printf("\n\n");
}

/*==============================================================================
 * SIGNAL HANDLER
 *============================================================================*/

static void signal_handler(int sig)
{
    (void)sig;
    g_running = false;
}

/*==============================================================================
 * MAIN
 *============================================================================*/

static void print_help(void)
{
    printf("%s v%s - GPU FTC Mining Client\n\n", MINER_NAME, MINER_VERSION);
    printf("Usage: ftc-miner-gpu -address <addr> [options]\n\n");
    printf("Options:\n");
    printf("  -address <addr>   Mining reward address (required)\n");
    printf("  -pool <host:port> Pool server (default: %s)\n", DEFAULT_POOL);
    printf("  -pool-pass <pass> Pool password (default: x)\n");
    printf("  -solo             Solo mining mode (no pool)\n");
    printf("  -node <host:port> Solo mode: connect to specific node\n");
    printf("  -devices <0,1,2>  GPU device IDs to use (default: all)\n");
    printf("  -intensity <n>    Mining intensity 1-100 (default: 100)\n");
    printf("  -no-color         Disable colored output\n");
    printf("  -list-devices     List available GPUs and exit\n");
    printf("  -help             Show this help\n\n");
    printf("Pool mining (default):\n");
    printf("  ftc-miner-gpu -address YOUR_WALLET\n");
    printf("  ftc-miner-gpu -address YOUR_WALLET -pool custom.pool.com:3333\n\n");
    printf("Solo mining:\n");
    printf("  ftc-miner-gpu -address YOUR_WALLET -solo\n");
    printf("  ftc-miner-gpu -address YOUR_WALLET -solo -node 127.0.0.1:17318\n\n");
}

static void parse_devices(const char* str)
{
    g_device_mask = 0;
    char* copy = strdup(str);
    char* token = strtok(copy, ",");

    while (token) {
        int dev = atoi(token);
        if (dev >= 0 && dev < 32) {
            g_device_mask |= (1 << dev);
        }
        token = strtok(NULL, ",");
    }

    free(copy);
}

int main(int argc, char* argv[])
{
    bool list_devices = false;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-address") == 0 && i + 1 < argc) {
            strncpy(g_miner_address, argv[++i], sizeof(g_miner_address) - 1);
        }
        else if (strcmp(argv[i], "-node") == 0 && i + 1 < argc) {
            strncpy(g_custom_node, argv[++i], sizeof(g_custom_node) - 1);
        }
        else if (strcmp(argv[i], "-pool") == 0 && i + 1 < argc) {
            strncpy(g_pool_url, argv[++i], sizeof(g_pool_url) - 1);
            g_mining_mode = MINING_MODE_POOL;
        }
        else if (strcmp(argv[i], "-pool-pass") == 0 && i + 1 < argc) {
            strncpy(g_pool_pass, argv[++i], sizeof(g_pool_pass) - 1);
        }
        else if (strcmp(argv[i], "-solo") == 0) {
            g_mining_mode = MINING_MODE_SOLO;
        }
        else if (strcmp(argv[i], "-devices") == 0 && i + 1 < argc) {
            parse_devices(argv[++i]);
        }
        else if (strcmp(argv[i], "-no-color") == 0) {
            g_color = false;
        }
        else if (strcmp(argv[i], "-list-devices") == 0) {
            list_devices = true;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_help();
            return 1;
        }
    }

    /* Initialize GPU subsystem */
    enable_ansi_colors();

    int gpu_count = ftc_gpu_init();
    if (gpu_count == 0) {
        fprintf(stderr, "Error: No GPUs detected. Ensure CUDA/OpenCL drivers are installed.\n");
        return 1;
    }

    if (list_devices) {
        printf("\n");
        ftc_gpu_print_devices();
        printf("\n");
        ftc_gpu_shutdown();
        return 0;
    }

    if (!g_miner_address[0]) {
        fprintf(stderr, "Error: Mining address required (-address)\n\n");
        print_help();
        ftc_gpu_shutdown();
        return 1;
    }

    ftc_address_t addr;
    if (!ftc_address_decode(g_miner_address, addr, NULL)) {
        fprintf(stderr, "Error: Invalid mining address\n");
        ftc_gpu_shutdown();
        return 1;
    }

    /* Initialize signals */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    if (!net_init()) {
        fprintf(stderr, "Error: Network initialization failed\n");
        ftc_gpu_shutdown();
        return 1;
    }

    /* Create GPU farm silently */
    g_farm = ftc_gpu_farm_new(g_device_mask);
    if (!g_farm) {
        fprintf(stderr, "Error: Failed to initialize GPU mining\n");
        ftc_gpu_shutdown();
        return 1;
    }

    /*==========================================================================
     * POOL MINING MODE
     *========================================================================*/
    if (g_mining_mode == MINING_MODE_POOL) {
        /* Parse pool URL */
        char pool_host[256] = {0};
        uint16_t pool_port = STRATUM_PORT;

        strncpy(pool_host, g_pool_url, sizeof(pool_host) - 1);
        char* colon = strchr(pool_host, ':');
        if (colon) {
            *colon = '\0';
            pool_port = (uint16_t)atoi(colon + 1);
        }

        strncpy(g_stratum.host, pool_host, sizeof(g_stratum.host) - 1);
        g_stratum.port = pool_port;
        strncpy(g_stratum.worker, g_miner_address, sizeof(g_stratum.worker) - 1);
        strncpy(g_stratum.password, g_pool_pass, sizeof(g_stratum.password) - 1);
        g_stratum.target_diff = 1.0;

        printf("Connecting to pool %s:%d...\n", pool_host, pool_port);

        /* Connect to pool with retry */
        while (g_running) {
            if (stratum_connect(&g_stratum)) {
                printf("Connected to pool, subscribing...\n");

                if (stratum_subscribe(&g_stratum)) {
                    printf("Subscribed (extranonce1=%s, en2_size=%d)\n",
                           g_stratum.extranonce1, g_stratum.extranonce2_size);

                    if (stratum_authorize(&g_stratum)) {
                        printf("Authorized as %s\n", g_stratum.worker);
                        break;
                    } else {
                        fprintf(stderr, "Authorization failed\n");
                    }
                } else {
                    fprintf(stderr, "Subscription failed\n");
                }
                stratum_disconnect(&g_stratum);
            }

            printf("Connection failed, retrying in 5s...\n");
            usleep(5000000);
        }

        if (!g_running) {
            stratum_disconnect(&g_stratum);
            ftc_gpu_farm_free(g_farm);
            ftc_gpu_shutdown();
            return 0;
        }

        /* Pool mining main loop */
        g_start_time = get_time_ms();
        int64_t last_stats = g_start_time;
        int64_t last_pool_poll = g_start_time;

        printf(C_CLEAR C_HOME C_HIDE_CUR);
        fflush(stdout);

        /* Wait for first job */
        printf("Waiting for work from pool...\n");
        while (g_running && !g_stratum.has_job) {
            stratum_poll(&g_stratum);
            usleep(100000);
        }

        while (g_running) {
            if (!g_stratum.connected) {
                /* Reconnect */
                log_to_buffer("Pool disconnected, reconnecting...");
                while (g_running && !g_stratum.connected) {
                    if (stratum_connect(&g_stratum) &&
                        stratum_subscribe(&g_stratum) &&
                        stratum_authorize(&g_stratum)) {
                        log_to_buffer("Reconnected to pool");
                        break;
                    }
                    usleep(5000000);
                }
                continue;
            }

            if (!g_stratum.has_job) {
                stratum_poll(&g_stratum);
                usleep(100000);
                continue;
            }

            /* Build work from stratum job */
            /* Calculate network difficulty from nbits (FTC formula)
             * FTC diff 1 target is 4096x larger than Bitcoin's */
            {
                uint32_t nbits = g_stratum.nbits;
                uint32_t exp = (nbits >> 24) & 0xff;
                uint32_t mant = nbits & 0x00ffffff;
                /* Bitcoin formula then multiply by 4096 for FTC */
                double target_d = (double)mant * pow(256.0, (double)(exp - 3));
                double max_target = (double)0x00ffff * pow(256.0, (double)(0x1d - 3));
                double btc_diff = max_target / target_d;
                g_difficulty = btc_diff * 4096.0;  /* FTC multiplier */
            }

            /* For FTC, we build header from pool data */
            uint8_t header[80];
            memset(header, 0, 80);

            /* Version (4 bytes) - use version from pool job */
            memcpy(header, &g_stratum.version, 4);

            /* Previous block hash (32 bytes) */
            memcpy(header + 4, g_stratum.prevhash, 32);

            /* Merkle root (32 bytes) - pool sends it in coinb1 field */
            memcpy(header + 36, g_stratum.coinb1, 32);

            /* Time (4 bytes) */
            memcpy(header + 68, &g_stratum.ntime, 4);

            /* Bits (4 bytes) */
            memcpy(header + 72, &g_stratum.nbits, 4);

            /* Nonce (4 bytes) - will be filled by miner */
            /* header[76-79] = 0 */

            /* Use POOL difficulty for share finding
             * FTC diff 1 nbits = 0x1e0fffff (genesis)
             * Pool diff is typically 1, network diff is ~65536 */
            ftc_hash256_t target;

            /* Calculate nbits for pool difficulty
             * FTC genesis (diff 1) = 0x1e0fffff
             * For higher diff, we reduce the target proportionally */
            double pool_diff = g_stratum.target_diff;
            if (pool_diff < 1.0) pool_diff = 1.0;

            /* For diff 1, use genesis bits; for higher diff, use network bits */
            uint32_t pool_nbits;
            if (pool_diff <= 1.0) {
                pool_nbits = 0x1e0fffff;  /* FTC genesis = diff 1 */
            } else {
                /* Scale down from network difficulty */
                pool_nbits = g_stratum.nbits;
            }

            ftc_bits_to_target(pool_nbits, target);
            ftc_gpu_farm_set_work(g_farm, header, target);

            char current_job[64];
            strncpy(current_job, g_stratum.job_id, sizeof(current_job) - 1);

            /* Mine until share found or new job */
            while (g_running && g_stratum.connected) {
                int64_t now;
                ftc_gpu_result_t result = ftc_gpu_farm_mine(g_farm);
                g_total_hashes += result.hashes;

                now = get_time_ms();

                /* Poll for new jobs */
                if (now - last_pool_poll >= 100) {
                    stratum_poll(&g_stratum);
                    last_pool_poll = now;

                    /* Check if job changed */
                    if (strcmp(current_job, g_stratum.job_id) != 0) {
                        char ts[16];
                        get_timestamp(ts, sizeof(ts));
                        log_to_buffer("[%s] New job: %s", ts, g_stratum.job_id);
                        g_stratum.extranonce2++;
                        break;  /* Get new work */
                    }
                }

                if (result.found) {
                    g_blocks_found++;

                    char hash_str[17];
                    for (int i = 0; i < 8; i++) sprintf(hash_str + i * 2, "%02x", result.hash[i]);
                    strncpy(g_last_block_hash, hash_str, 16);

                    /* Submit share to pool */
                    stratum_submit_share(&g_stratum, result.nonce, g_stratum.ntime);

                    char ts[16];
                    get_timestamp(ts, sizeof(ts));
                    log_to_buffer("[%s] Share submitted: %s", ts, hash_str);

                    g_blocks_accepted = g_stratum.shares_accepted;

                    /* Increment extranonce2 for next share */
                    g_stratum.extranonce2++;
                }

                /* Update display */
                if (now - last_stats >= 200) {
                    /* Update stats from stratum */
                    g_blocks_accepted = g_stratum.shares_accepted;
                    draw_static_display();
                    last_stats = now;
                }
            }
        }

        stratum_disconnect(&g_stratum);
    }
    /*==========================================================================
     * SOLO MINING MODE
     *========================================================================*/
    else {
        /* Discover nodes and connect with retry */
        printf("Connecting to FTC network...\n");

        while (g_running) {
            discover_nodes();

            if (g_node_count == 0) {
                printf("Searching for nodes... (retry in 3s)\n");
                usleep(3000000);
                continue;
            }

            update_node_latencies();
            g_active_node = select_best_node();

            if (g_active_node < 0) {
                printf("Nodes unreachable, retrying in 3s...\n");
                usleep(3000000);
                continue;
            }

            if (get_node_info(g_active_node)) {
                printf("Connected to %s (latency: %dms)\n",
                       g_nodes[g_active_node].ip,
                       g_nodes[g_active_node].latency_ms);
                break;  /* Successfully connected */
            }

            printf("Connection failed, retrying in 3s...\n");
            usleep(3000000);
        }

        if (!g_running) {
            ftc_gpu_farm_free(g_farm);
            ftc_gpu_shutdown();
            return 0;
        }

        /* Start mining - clear screen immediately for static display */
        g_start_time = get_time_ms();
        int64_t last_stats = g_start_time;
        int64_t last_latency_check = g_start_time;

        printf(C_CLEAR C_HOME C_HIDE_CUR);
        fflush(stdout);

        /* Draw initial display before first block template */
        draw_static_display();

        while (g_running) {
            uint32_t height = 0;
            ftc_block_t* block = get_block_template(g_active_node, &height);

            if (!block) {
                g_nodes[g_active_node].failures++;
                if (g_nodes[g_active_node].failures > 5) {
                    g_nodes[g_active_node].connected = false;
                    char ts[16];
                    get_timestamp(ts, sizeof(ts));
                    log_to_buffer("[%s] Node %s offline, searching...", ts, g_nodes[g_active_node].ip);
                    draw_static_display();
                    g_active_node = select_best_node();
                    if (g_active_node < 0) {
                        log_to_buffer("[%s] All nodes offline. Retrying in 5s...", ts);
                        draw_static_display();
                        usleep(5000000);
                        update_node_latencies();
                        g_active_node = select_best_node();
                        continue;
                    }
                    log_to_buffer("[%s] Switched to %s", ts, g_nodes[g_active_node].ip);
                    draw_static_display();
                }
                usleep(2000000);
                continue;
            }

            g_current_height = height;

            /* Update node info (difficulty, etc) on each new block */
            get_node_info(g_active_node);

            /* Prepare work */
            uint8_t header[80];
            ftc_block_header_serialize(&block->header, header);

            ftc_hash256_t target;
            ftc_bits_to_target(block->header.bits, target);

            ftc_gpu_farm_set_work(g_farm, header, target);

            /* Mine until block found or new block from network */
            int64_t last_block_check = get_time_ms();
            while (g_running) {
                int64_t now;
                ftc_gpu_result_t result = ftc_gpu_farm_mine(g_farm);
                g_total_hashes += result.hashes;

                now = get_time_ms();

                if (result.found) {
                    block->header.nonce = result.nonce;
                    g_blocks_found++;

                    char hash_str[17];
                    for (int i = 0; i < 8; i++) sprintf(hash_str + i * 2, "%02x", result.hash[i]);
                    strncpy(g_last_block_hash, hash_str, 16);

                    bool accepted = submit_block(g_active_node, block);
                    if (accepted) {
                        g_blocks_accepted++;
                        g_current_height = height + 1;
                    }

                    log_share_found(height, g_last_block_hash, accepted);

                    /* Update display after block found */
                    draw_static_display();
                    last_stats = now;
                    break;
                }

                /* Update display every 200ms for responsive UI */
                if (now - last_stats >= 200) {
                    draw_static_display();
                    last_stats = now;
                }

                /* Check for new block from network every 5 seconds */
                if (now - last_block_check >= 5000) {
                    if (get_node_info(g_active_node) && g_nodes[g_active_node].height > height) {
                        /* Log network block */
                        char ts[16];
                        get_timestamp(ts, sizeof(ts));
                        log_to_buffer("[%s] NETWORK h=%u (new block from other miner)", ts, g_nodes[g_active_node].height);
                        g_current_height = g_nodes[g_active_node].height;
                        draw_static_display();
                        break;
                    }
                    last_block_check = now;
                }

                /* Check latency every 30 seconds */
                if (now - last_latency_check >= LATENCY_CHECK_INTERVAL) {
                    update_node_latencies();
                    int best = select_best_node();
                    if (best >= 0 && best != g_active_node) {
                        if (g_nodes[best].latency_ms + 100 < g_nodes[g_active_node].latency_ms) {
                            g_active_node = best;
                        }
                    }
                    last_latency_check = now;
                }
            }

            ftc_block_free(block);
            /* No delay - immediately get next block template */
        }
    }

    print_final_stats();

    ftc_gpu_farm_free(g_farm);
    ftc_gpu_shutdown();

    return 0;
}
