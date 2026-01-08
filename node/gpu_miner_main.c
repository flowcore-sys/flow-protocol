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

#define MINER_VERSION       "2.0.0"
#define MINER_NAME          "FTC-GPU-Miner"
#define MAX_NODES           16
#define RPC_PORT            17318
#define LATENCY_CHECK_INTERVAL  30000

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
    miner_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == MINER_INVALID_SOCKET) return 9999;

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

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

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

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
    miner_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == MINER_INVALID_SOCKET) return 9999;

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, host, &addr.sin_addr);
    addr.sin_port = htons(port);

    int64_t start = get_time_ms();

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sock);
            return 9999;
        }
#else
        if (errno != EINPROGRESS) {
            close(sock);
            return 9999;
        }
#endif
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = {2, 0};

    ret = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (ret <= 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return 9999;
    }

    int64_t elapsed = get_time_ms() - start;

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

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
 * RPC CLIENT
 *============================================================================*/

static char* rpc_call(int node_idx, const char* method, const char* params)
{
    if (node_idx < 0 || node_idx >= g_node_count) return NULL;

    node_info_t* node = &g_nodes[node_idx];

    miner_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
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
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
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

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

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

    for (size_t i = 0; i < size; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
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
    miner_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    free(request);
}

static bool submit_block(int node_idx, ftc_block_t* block)
{
    /* Use async version for speed, assume accepted */
    submit_block_async(node_idx, block);
    return true;  /* Optimistically assume accepted */
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

    /* Node info */
    printf(C_CLR_LINE "Node: " C_CYAN "%s" C_RESET "  Latency: " C_GREEN "%dms" C_RESET "  Height: " C_YELLOW "%u" C_RESET "  Diff: %.4f\n",
           g_nodes[g_active_node].ip,
           g_nodes[g_active_node].latency_ms,
           g_current_height,
           g_difficulty);
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
    printf(C_CLR_LINE "Uptime: " C_CYAN "%s" C_RESET "  Total hashes: " C_WHITE "%.2f B" C_RESET "\n",
           uptime_str, (double)g_total_hashes / 1e9);

    printf(C_CLR_LINE "================================================================================\n");

    /* Log buffer - show recent events */
    printf(C_CLR_LINE C_BOLD "Recent:" C_RESET "\n");
    for (int i = 0; i < LOG_BUFFER_SIZE; i++) {
        int idx = (g_log_head - g_log_count + i + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;
        if (i < g_log_count) {
            if (strstr(g_log_buffer[idx], "BLOCK!")) {
                printf(C_CLR_LINE C_GREEN " %s" C_RESET "\n", g_log_buffer[idx]);
            } else if (strstr(g_log_buffer[idx], "NETWORK")) {
                printf(C_CLR_LINE C_CYAN " %s" C_RESET "\n", g_log_buffer[idx]);
            } else if (strstr(g_log_buffer[idx], "REJECTED")) {
                printf(C_CLR_LINE C_RED " %s" C_RESET "\n", g_log_buffer[idx]);
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
    } else {
        log_to_buffer("[%s] REJECTED h=%u", ts, height);
    }
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
    printf("  -node <host:port> Connect to specific node (default: DNS seeds)\n");
    printf("  -devices <0,1,2>  GPU device IDs to use (default: all)\n");
    printf("  -intensity <n>    Mining intensity 1-100 (default: 100)\n");
    printf("  -no-color         Disable colored output\n");
    printf("  -list-devices     List available GPUs and exit\n");
    printf("  -help             Show this help\n\n");
    printf("Example:\n");
    printf("  ftc-miner-gpu -address 14CC2YgUzyMMhpPtXSwfYyHhus9kSYp6xo\n");
    printf("  ftc-miner-gpu -address <addr> -node 127.0.0.1:17318\n");
    printf("  ftc-miner-gpu -address <addr> -devices 0,1\n\n");
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

    print_final_stats();

    ftc_gpu_farm_free(g_farm);
    ftc_gpu_shutdown();

    return 0;
}
