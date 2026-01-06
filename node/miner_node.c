/**
 * FTC Miner - Professional Mining Client
 *
 * Features:
 * - Auto DNS seed discovery
 * - Node latency monitoring
 * - Automatic failover to best node
 * - Rigel-style real-time display
 *
 * Usage: ftc-miner -address <addr> [-threads <n>]
 */

#include "../include/ftc.h"
#include "../src/core/block.h"
#include "../src/crypto/keccak256.h"
#include "../src/crypto/keys.h"
#include "miner_node.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET miner_socket_t;
#define MINER_INVALID_SOCKET INVALID_SOCKET
#define usleep(x) Sleep((x)/1000)

/* Enable ANSI colors in Windows console */
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
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
typedef int miner_socket_t;
#define MINER_INVALID_SOCKET -1
#define enable_ansi_colors() ((void)0)
#endif

/*==============================================================================
 * ANSI COLORS
 *============================================================================*/

#define C_RESET     "\x1b[0m"
#define C_BOLD      "\x1b[1m"
#define C_DIM       "\x1b[2m"
#define C_RED       "\x1b[31m"
#define C_GREEN     "\x1b[32m"
#define C_YELLOW    "\x1b[33m"
#define C_BLUE      "\x1b[34m"
#define C_MAGENTA   "\x1b[35m"
#define C_CYAN      "\x1b[36m"
#define C_WHITE     "\x1b[37m"
#define C_GRAY      "\x1b[90m"

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define MINER_VERSION       "1.1.0"
#define MINER_NAME          "FTC-Miner"
#define MAX_NODES           16
#define RPC_PORT            17318
#define LATENCY_CHECK_INTERVAL  30000   /* 30 seconds */
#define NODE_SWITCH_THRESHOLD   100     /* ms - switch if better by this much */

/* DNS Seeds */
static const char* DNS_SEEDS[] = {
    "seed.flowprotocol.net",
    "seed1.flowprotocol.net",
    "seed2.flowprotocol.net",
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
static bool g_color = true;

/* Statistics */
static miner_stats_t g_stats = {0};
static int64_t g_start_time = 0;
static uint32_t g_current_height = 0;
static int g_peer_count = 0;
static char g_last_block_hash[17] = {0};
static int64_t g_last_log_time = 0;

/* Get timestamp string [HH:MM:SS] */
static void get_timestamp(char* buf, size_t len)
{
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    snprintf(buf, len, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* Log with timestamp */
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
static int64_t g_last_block_time = 0;
static int64_t g_last_latency_check = 0;
static double g_difficulty = 1.0;

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
 * NETWORK INITIALIZATION
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

/*==============================================================================
 * DNS RESOLUTION
 *============================================================================*/

static int resolve_dns_seed(const char* hostname, node_info_t* nodes, int max_nodes)
{
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return 0;
    }

    int count = 0;
    for (rp = result; rp != NULL && count < max_nodes; rp = rp->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
        char ip[64];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

        /* Check if already in list */
        bool exists = false;
        for (int i = 0; i < count; i++) {
            if (strcmp(nodes[i].ip, ip) == 0) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            strncpy(nodes[count].host, hostname, sizeof(nodes[count].host) - 1);
            strncpy(nodes[count].ip, ip, sizeof(nodes[count].ip) - 1);
            nodes[count].port = RPC_PORT;
            nodes[count].latency_ms = 9999;
            nodes[count].active = true;
            nodes[count].connected = false;
            nodes[count].height = 0;
            nodes[count].failures = 0;
            count++;
        }
    }

    freeaddrinfo(result);
    return count;
}

static bool ip_exists(const char* ip)
{
    for (int i = 0; i < g_node_count; i++) {
        if (strcmp(g_nodes[i].ip, ip) == 0) return true;
    }
    return false;
}

static void discover_nodes(void)
{
    g_node_count = 0;

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

            /* Skip duplicates across all seeds */
            if (ip_exists(ip)) continue;

            strncpy(g_nodes[g_node_count].host, DNS_SEEDS[i], sizeof(g_nodes[g_node_count].host) - 1);
            strncpy(g_nodes[g_node_count].ip, ip, sizeof(g_nodes[g_node_count].ip) - 1);
            g_nodes[g_node_count].port = RPC_PORT;
            g_nodes[g_node_count].latency_ms = 9999;
            g_nodes[g_node_count].active = true;
            g_nodes[g_node_count].connected = false;
            g_nodes[g_node_count].height = 0;
            g_nodes[g_node_count].failures = 0;
            g_node_count++;
        }
        freeaddrinfo(result);
    }
}

/*==============================================================================
 * LATENCY MEASUREMENT
 *============================================================================*/

static int measure_latency(const char* host, uint16_t port)
{
    miner_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == MINER_INVALID_SOCKET) return 9999;

    /* Set non-blocking mode */
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

    /* Wait for connect with select() - 2 second timeout */
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
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {5, 0};
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

    char* body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;
        memmove(response, body, strlen(body) + 1);
    }

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

static bool submit_block(int node_idx, ftc_block_t* block)
{
    size_t size = ftc_block_serialize(block, NULL, 0);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return false;

    ftc_block_serialize(block, data, size);

    char* hex = (char*)malloc(size * 2 + 1);
    if (!hex) {
        free(data);
        return false;
    }

    for (size_t i = 0; i < size; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    free(data);

    char* params = (char*)malloc(size * 2 + 32);
    if (!params) {
        free(hex);
        return false;
    }

    sprintf(params, "[\"%s\"]", hex);
    free(hex);

    char* response = rpc_call(node_idx, "submitblock", params);
    free(params);

    if (!response) return false;

    bool success = strstr(response, "\"result\":null") != NULL;
    free(response);
    return success;
}

/*==============================================================================
 * DISPLAY (Rigel-style logging)
 *============================================================================*/

static void print_header(void)
{
    printf("\n");
    if (g_color) printf(C_CYAN C_BOLD);
    printf("  FTC-Miner v%s", MINER_VERSION);
    if (g_color) printf(C_RESET);
    printf(" - Keccak-256 Solo Miner\n");
    printf("  ================================================\n");
    if (g_color) printf(C_WHITE);
    printf("  Address: %s\n", g_miner_address);
    if (g_color) printf(C_RESET);
    printf("\n");
}

static void log_stats(void)
{
    int64_t elapsed = get_time_ms() - g_start_time;
    double hashrate = elapsed > 0 ? (double)g_stats.total_hashes * 1000.0 / elapsed : 0;

    char hr_str[32];
    format_hashrate(hashrate, hr_str, sizeof(hr_str));

    if (g_color) {
        log_info(C_GREEN "%s" C_RESET " | shares " C_CYAN "%llu" C_RESET "/" C_YELLOW "%llu" C_RESET " | height " C_MAGENTA "%u" C_RESET " | %s\n",
                 hr_str,
                 (unsigned long long)g_stats.blocks_accepted,
                 (unsigned long long)g_stats.blocks_found,
                 g_current_height,
                 g_nodes[g_active_node].ip);
    } else {
        log_info("%s | shares %llu/%llu | height %u | %s\n",
                 hr_str,
                 (unsigned long long)g_stats.blocks_accepted,
                 (unsigned long long)g_stats.blocks_found,
                 g_current_height,
                 g_nodes[g_active_node].ip);
    }
}

static void log_share_found(uint32_t height, const char* hash, bool accepted)
{
    if (accepted) {
        if (g_color) {
            log_info(C_GREEN C_BOLD "BLOCK FOUND!" C_RESET " #%u hash=%s...\n", height, hash);
        } else {
            log_info("BLOCK FOUND! #%u hash=%s...\n", height, hash);
        }
    } else {
        if (g_color) {
            log_info(C_RED "block rejected" C_RESET " #%u\n", height);
        } else {
            log_info("block rejected #%u\n", height);
        }
    }
}

static void print_final_stats(void)
{
    int64_t elapsed = get_time_ms() - g_start_time;
    double hashrate = elapsed > 0 ? (double)g_stats.total_hashes * 1000.0 / elapsed : 0;

    char hr_str[32], time_str[32];
    format_hashrate(hashrate, hr_str, sizeof(hr_str));
    format_time(elapsed, time_str, sizeof(time_str));

    printf("\n");
    if (g_color) printf(C_CYAN);
    printf("  == Session Summary ==================================\n");
    if (g_color) printf(C_RESET);

    printf("  Duration:    %s\n", time_str);
    printf("  Avg Speed:   %s\n", hr_str);
    printf("  Blocks:      %llu found, %llu accepted",
           (unsigned long long)g_stats.blocks_found,
           (unsigned long long)g_stats.blocks_accepted);

    if (g_stats.blocks_found > 0) {
        double rate = (double)g_stats.blocks_accepted / g_stats.blocks_found * 100.0;
        printf(" (%.0f%%)", rate);
    }
    printf("\n\n");
}

/*==============================================================================
 * MINING LOOP
 *============================================================================*/

static void mine_block(ftc_block_t* block, uint32_t height)
{
    ftc_hash256_t target;
    ftc_bits_to_target(block->header.bits, target);

    uint8_t header[80];
    ftc_block_header_serialize(&block->header, header);

    ftc_hash256_t hash;
    int64_t last_log = get_time_ms();

    for (uint32_t nonce = 0; nonce < 0xFFFFFFFF && g_running; nonce++) {
        header[76] = (uint8_t)(nonce);
        header[77] = (uint8_t)(nonce >> 8);
        header[78] = (uint8_t)(nonce >> 16);
        header[79] = (uint8_t)(nonce >> 24);

        ftc_keccak256_double(header, 80, hash);
        g_stats.total_hashes++;
        g_stats.current_nonce = nonce;

        bool valid = true;
        for (int i = 31; i >= 0; i--) {
            if (hash[i] < target[i]) break;
            if (hash[i] > target[i]) { valid = false; break; }
        }

        if (valid) {
            block->header.nonce = nonce;
            g_stats.blocks_found++;

            ftc_block_hash(block, hash);
            char hash_str[17];
            for (int i = 0; i < 8; i++) sprintf(hash_str + i * 2, "%02x", hash[i]);
            strncpy(g_last_block_hash, hash_str, 16);

            bool accepted = submit_block(g_active_node, block);
            if (accepted) {
                g_stats.blocks_accepted++;
                g_last_block_time = get_time_ms();
                g_current_height = height + 1;
            }

            log_share_found(height, g_last_block_hash, accepted);
            return;
        }

        int64_t now = get_time_ms();

        /* Log stats every 10 seconds */
        if (now - last_log >= 10000) {
            log_stats();
            last_log = now;

            /* Update node info */
            get_node_info(g_active_node);

            /* Check if we should switch nodes */
            if (now - g_last_latency_check >= LATENCY_CHECK_INTERVAL) {
                update_node_latencies();
                int best = select_best_node();
                if (best >= 0 && best != g_active_node) {
                    if (g_nodes[best].latency_ms + NODE_SWITCH_THRESHOLD < g_nodes[g_active_node].latency_ms) {
                        log_info("Switching to %s (%dms)\n", g_nodes[best].ip, g_nodes[best].latency_ms);
                        g_active_node = best;
                    }
                }
                g_last_latency_check = now;
            }
        }
    }
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
    printf("%s v%s - Professional FTC Mining Client\n\n", MINER_NAME, MINER_VERSION);
    printf("Usage: ftc-miner -address <addr> [options]\n\n");
    printf("Options:\n");
    printf("  -address <addr>  Mining reward address (required)\n");
    printf("  -no-color        Disable colored output\n");
    printf("  -help            Show this help\n\n");
    printf("The miner automatically discovers nodes via DNS seeds.\n\n");
    printf("Example:\n");
    printf("  ftc-miner -address 14CC2YgUzyMMhpPtXSwfYyHhus9kSYp6xo\n\n");
}

int main(int argc, char* argv[])
{
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-address") == 0 && i + 1 < argc) {
            strncpy(g_miner_address, argv[++i], sizeof(g_miner_address) - 1);
        }
        else if (strcmp(argv[i], "-no-color") == 0) {
            g_color = false;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_help();
            return 1;
        }
    }

    if (!g_miner_address[0]) {
        fprintf(stderr, "Error: Mining address required (-address)\n\n");
        print_help();
        return 1;
    }

    ftc_address_t addr;
    if (!ftc_address_decode(g_miner_address, addr, NULL)) {
        fprintf(stderr, "Error: Invalid mining address\n");
        return 1;
    }

    /* Initialize */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    if (!net_init()) {
        fprintf(stderr, "Error: Network initialization failed\n");
        return 1;
    }

    enable_ansi_colors();
    print_header();

    /* Discover nodes */
    log_info("Discovering nodes via DNS seeds...\n");
    discover_nodes();

    if (g_node_count == 0) {
        log_info("No nodes found. Check your internet connection.\n");
        return 1;
    }

    log_info("Found %d node(s), measuring latency...\n", g_node_count);
    update_node_latencies();

    /* Select best node */
    g_active_node = select_best_node();
    if (g_active_node < 0) {
        log_info("All nodes unreachable.\n");
        return 1;
    }

    /* Show nodes */
    for (int i = 0; i < g_node_count && i < 4; i++) {
        const char* marker = (i == g_active_node) ? "*" : " ";
        if (g_nodes[i].connected) {
            log_info(" %s %s (%dms)\n", marker, g_nodes[i].ip, g_nodes[i].latency_ms);
        }
    }

    /* Get initial info */
    if (!get_node_info(g_active_node)) {
        log_info("Cannot connect to node\n");
        return 1;
    }

    log_info("Connected to %s | height %u | diff %.2f\n",
             g_nodes[g_active_node].ip, g_current_height, g_difficulty);

    /* Start mining */
    g_start_time = get_time_ms();
    g_last_latency_check = g_start_time;
    g_last_log_time = g_start_time;
    memset(&g_stats, 0, sizeof(g_stats));

    log_info("Mining started\n");
    int64_t last_stats = g_start_time;

    while (g_running) {
        uint32_t height = 0;
        ftc_block_t* block = get_block_template(g_active_node, &height);

        if (!block) {
            /* Try to find another node */
            g_nodes[g_active_node].failures++;
            if (g_nodes[g_active_node].failures > 3) {
                g_nodes[g_active_node].connected = false;
                log_info("Node %s offline, searching...\n", g_nodes[g_active_node].ip);
                g_active_node = select_best_node();
                if (g_active_node < 0) {
                    log_info("All nodes offline. Retrying in 5s...\n");
                    usleep(5000000);
                    update_node_latencies();
                    g_active_node = select_best_node();
                    continue;
                }
                log_info("Switched to %s\n", g_nodes[g_active_node].ip);
            }
            usleep(2000000);
            continue;
        }

        g_current_height = height;
        mine_block(block, height);
        ftc_block_free(block);

        /* Log stats every 10 seconds (in main loop for fast block finding) */
        int64_t now = get_time_ms();
        if (now - last_stats >= 10000) {
            log_stats();
            last_stats = now;
        }

        if (g_running) usleep(100000);
    }

    print_final_stats();

    return 0;
}
