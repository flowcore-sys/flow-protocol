/**
 * FTC Wallet CLI
 *
 * Command-line wallet for sending transactions via active nodes.
 * Supports auto-discovery and failover like the GPU miner.
 *
 * Usage:
 *   ftc-wallet -node <ip:port> balance <address>
 *   ftc-wallet -node <ip:port> send <privkey> <pubkey> <to_address> <amount> [fee]
 *   ftc-wallet -node <ip:port> listunspent <address>
 */

#include "../include/ftc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET wallet_socket_t;
#define WALLET_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
typedef int wallet_socket_t;
#define WALLET_INVALID_SOCKET -1
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define WALLET_VERSION      "1.0.0"
#define DEFAULT_RPC_PORT    17318
#define MAX_NODES           16
#define RESPONSE_BUFFER     65536

/*==============================================================================
 * NODE MANAGEMENT
 *============================================================================*/

typedef struct {
    char ip[64];
    uint16_t port;
    int latency_ms;
    bool active;
} node_info_t;

static node_info_t g_nodes[MAX_NODES];
static int g_node_count = 0;
static int g_active_node = -1;

/*==============================================================================
 * SOCKET HELPERS
 *============================================================================*/

static inline void close_socket(wallet_socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

static inline wallet_socket_t create_tcp_socket(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static int64_t get_time_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/*==============================================================================
 * RPC CLIENT
 *============================================================================*/

static char* rpc_call(int node_idx, const char* method, const char* params)
{
    if (node_idx < 0 || node_idx >= g_node_count) return NULL;

    node_info_t* node = &g_nodes[node_idx];

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", node->port);

    if (getaddrinfo(node->ip, port_str, &hints, &result) != 0) {
        return NULL;
    }

    wallet_socket_t sock = create_tcp_socket();
    if (sock == WALLET_INVALID_SOCKET) {
        freeaddrinfo(result);
        return NULL;
    }

#ifdef _WIN32
    DWORD timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        close_socket(sock);
        return NULL;
    }
    freeaddrinfo(result);

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

    char* response = (char*)malloc(RESPONSE_BUFFER);
    if (!response) {
        close_socket(sock);
        return NULL;
    }

    int total = 0;
    while (total < RESPONSE_BUFFER - 1) {
        int ret = recv(sock, response + total, RESPONSE_BUFFER - 1 - total, 0);
        if (ret <= 0) break;
        total += ret;
        response[total] = '\0';
        char* body = strstr(response, "\r\n\r\n");
        if (body && strrchr(body, '}')) break;
    }
    response[total] = '\0';

    close_socket(sock);

    if (total == 0) {
        free(response);
        return NULL;
    }

    char* body = strstr(response, "\r\n\r\n");
    if (!body) {
        free(response);
        return NULL;
    }

    body += 4;
    memmove(response, body, strlen(body) + 1);
    return response;
}

/*==============================================================================
 * NODE DISCOVERY
 *============================================================================*/

static int measure_latency(const char* ip, uint16_t port)
{
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(ip, port_str, &hints, &result) != 0) {
        return 9999;
    }

    wallet_socket_t sock = create_tcp_socket();
    if (sock == WALLET_INVALID_SOCKET) {
        freeaddrinfo(result);
        return 9999;
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int64_t start = get_time_ms();
    connect(sock, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = {3, 0};

    int ret = select((int)sock + 1, NULL, &wset, NULL, &tv);
    int64_t elapsed = get_time_ms() - start;

    close_socket(sock);

    return (ret > 0) ? (int)elapsed : 9999;
}

static void add_node(const char* ip, uint16_t port)
{
    /* Check if already exists */
    for (int i = 0; i < g_node_count; i++) {
        if (strcmp(g_nodes[i].ip, ip) == 0 && g_nodes[i].port == port) {
            return;
        }
    }

    if (g_node_count >= MAX_NODES) return;

    strncpy(g_nodes[g_node_count].ip, ip, sizeof(g_nodes[g_node_count].ip) - 1);
    g_nodes[g_node_count].port = port;
    g_nodes[g_node_count].latency_ms = measure_latency(ip, port);
    g_nodes[g_node_count].active = (g_nodes[g_node_count].latency_ms < 5000);
    g_node_count++;
}

static void discover_peers_from_node(int node_idx)
{
    char* response = rpc_call(node_idx, "getpeerinfo", "[]");
    if (!response) return;

    char* ptr = strstr(response, "\"result\"");
    if (!ptr) {
        free(response);
        return;
    }

    while ((ptr = strstr(ptr, "\"addr\"")) != NULL && g_node_count < MAX_NODES) {
        ptr += 7;
        while (*ptr == ' ' || *ptr == ':' || *ptr == '"') ptr++;

        char ip[64] = {0};
        int i = 0;
        while (*ptr && *ptr != '"' && i < 63) {
            ip[i++] = *ptr++;
        }
        ip[i] = '\0';

        if (strlen(ip) < 7) continue;

        /* Find port */
        uint16_t port = DEFAULT_RPC_PORT;
        char* port_str = strstr(ptr, "\"port\"");
        if (port_str) {
            port_str += 6;
            while (*port_str == ' ' || *port_str == ':') port_str++;
            port = (uint16_t)atoi(port_str);
        }

        /* Skip local addresses */
        if (strcmp(ip, "0.0.0.0") == 0) continue;
        if (strncmp(ip, "127.", 4) == 0) continue;

        add_node(ip, port);
    }

    free(response);
}

static int select_best_node(void)
{
    int best = -1;
    int best_latency = 99999;

    for (int i = 0; i < g_node_count; i++) {
        if (g_nodes[i].active && g_nodes[i].latency_ms < best_latency) {
            best_latency = g_nodes[i].latency_ms;
            best = i;
        }
    }

    return best;
}

/*==============================================================================
 * WALLET COMMANDS
 *============================================================================*/

static int cmd_balance(const char* address)
{
    if (g_active_node < 0) {
        printf("Error: No active node\n");
        return 1;
    }

    char params[256];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    char* response = rpc_call(g_active_node, "getbalance", params);
    if (!response) {
        printf("Error: Failed to connect to node\n");
        return 1;
    }

    /* Parse result */
    char* result = strstr(response, "\"result\"");
    if (result) {
        result = strchr(result, ':');
        if (result) {
            double balance = strtod(result + 1, NULL);
            printf("Balance: %.8f FTC\n", balance);
        }
    }

    char* error = strstr(response, "\"error\"");
    if (error && !strstr(error, "null")) {
        printf("Error: %s\n", response);
    }

    free(response);
    return 0;
}

static int cmd_listunspent(const char* address)
{
    if (g_active_node < 0) {
        printf("Error: No active node\n");
        return 1;
    }

    char params[256];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    char* response = rpc_call(g_active_node, "listunspent", params);
    if (!response) {
        printf("Error: Failed to connect to node\n");
        return 1;
    }

    /* Pretty print UTXOs */
    printf("UTXOs for %s:\n", address);
    printf("----------------------------------------\n");

    char* ptr = response;
    int count = 0;
    while ((ptr = strstr(ptr, "\"txid\"")) != NULL) {
        count++;
        ptr += 7;
        while (*ptr == ' ' || *ptr == ':' || *ptr == '"') ptr++;

        char txid[65] = {0};
        int i = 0;
        while (*ptr && *ptr != '"' && i < 64) txid[i++] = *ptr++;

        /* Find vout */
        char* vout_ptr = strstr(ptr, "\"vout\"");
        int vout = 0;
        if (vout_ptr) {
            vout_ptr += 6;
            while (*vout_ptr == ' ' || *vout_ptr == ':') vout_ptr++;
            vout = atoi(vout_ptr);
        }

        /* Find amount */
        char* amount_ptr = strstr(ptr, "\"amount\"");
        double amount = 0;
        if (amount_ptr) {
            amount_ptr += 8;
            while (*amount_ptr == ' ' || *amount_ptr == ':') amount_ptr++;
            amount = strtod(amount_ptr, NULL);
        }

        printf("#%d: %.8f FTC\n", count, amount);
        printf("    txid: %s\n", txid);
        printf("    vout: %d\n", vout);
        printf("\n");
    }

    if (count == 0) {
        printf("No UTXOs found\n");
    }

    free(response);
    return 0;
}

static int cmd_send(const char* privkey, const char* pubkey, const char* to_addr,
                    double amount, double fee)
{
    if (g_active_node < 0) {
        printf("Error: No active node\n");
        return 1;
    }

    printf("Sending %.8f FTC to %s (fee: %.8f FTC)\n", amount, to_addr, fee);
    printf("Using node: %s:%d\n", g_nodes[g_active_node].ip, g_nodes[g_active_node].port);

    char params[1024];
    snprintf(params, sizeof(params),
             "[\"%s\", \"%s\", \"%s\", %.8f, %.8f]",
             privkey, pubkey, to_addr, amount, fee);

    char* response = rpc_call(g_active_node, "sendtoaddress", params);
    if (!response) {
        printf("Error: Failed to connect to node\n");

        /* Try failover */
        printf("Attempting failover...\n");
        for (int i = 0; i < g_node_count; i++) {
            if (i == g_active_node || !g_nodes[i].active) continue;

            printf("Trying %s:%d...\n", g_nodes[i].ip, g_nodes[i].port);
            response = rpc_call(i, "sendtoaddress", params);
            if (response) {
                g_active_node = i;
                break;
            }
        }

        if (!response) {
            printf("Error: All nodes failed\n");
            return 1;
        }
    }

    /* Check for error */
    char* error = strstr(response, "\"error\"");
    if (error) {
        char* null_check = strstr(error, "null");
        if (!null_check || null_check > error + 20) {
            /* Has error */
            char* msg = strstr(error, "\"message\"");
            if (msg) {
                msg = strchr(msg, ':');
                if (msg) {
                    msg++;
                    while (*msg == ' ' || *msg == '"') msg++;
                    char* end = strchr(msg, '"');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg);
                }
            } else {
                printf("Error: %s\n", response);
            }
            free(response);
            return 1;
        }
    }

    /* Success - extract txid */
    char* result = strstr(response, "\"result\"");
    if (result) {
        result = strchr(result, ':');
        if (result) {
            result++;
            while (*result == ' ' || *result == '"') result++;
            char* end = strchr(result, '"');
            if (end) *end = '\0';
            printf("Success! Transaction ID:\n%s\n", result);
        }
    }

    free(response);
    return 0;
}

static int cmd_info(void)
{
    if (g_active_node < 0) {
        printf("Error: No active node\n");
        return 1;
    }

    char* response = rpc_call(g_active_node, "getinfo", "[]");
    if (!response) {
        printf("Error: Failed to connect to node\n");
        return 1;
    }

    printf("Node: %s:%d\n", g_nodes[g_active_node].ip, g_nodes[g_active_node].port);
    printf("Latency: %d ms\n", g_nodes[g_active_node].latency_ms);
    printf("\n");

    /* Parse and display info */
    char* blocks = strstr(response, "\"blocks\"");
    if (blocks) {
        blocks = strchr(blocks, ':');
        if (blocks) printf("Block height: %d\n", atoi(blocks + 1));
    }

    char* diff = strstr(response, "\"difficulty\"");
    if (diff) {
        diff = strchr(diff, ':');
        if (diff) printf("Difficulty: %.2f\n", strtod(diff + 1, NULL));
    }

    char* conn = strstr(response, "\"connections\"");
    if (conn) {
        conn = strchr(conn, ':');
        if (conn) printf("Connections: %d\n", atoi(conn + 1));
    }

    free(response);
    return 0;
}

/*==============================================================================
 * MAIN
 *============================================================================*/

static void print_help(void)
{
    printf("FTC Wallet CLI v%s\n", WALLET_VERSION);
    printf("\n");
    printf("Usage: ftc-wallet -node <ip:port> <command> [args...]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -node <ip:port>   Node RPC address (required)\n");
    printf("  -discover         Auto-discover additional nodes\n");
    printf("\n");
    printf("Commands:\n");
    printf("  info                              Show node info\n");
    printf("  balance <address>                 Check address balance\n");
    printf("  listunspent <address>             List UTXOs for address\n");
    printf("  send <privkey> <pubkey> <to> <amount> [fee]\n");
    printf("                                    Send FTC transaction\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ftc-wallet -node 15.164.228.225:17318 info\n");
    printf("  ftc-wallet -node 15.164.228.225:17318 balance 1ABC...\n");
    printf("  ftc-wallet -node 15.164.228.225:17318 send <priv> <pub> <to> 10.0\n");
    printf("\n");
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if (argc < 2) {
        print_help();
        return 1;
    }

    /* Parse arguments */
    char* node_addr = NULL;
    bool auto_discover = false;
    int cmd_start = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-node") == 0 && i + 1 < argc) {
            node_addr = argv[++i];
            cmd_start = i + 1;
        }
        else if (strcmp(argv[i], "-discover") == 0) {
            auto_discover = true;
            cmd_start = i + 1;
        }
        else if (argv[i][0] != '-') {
            cmd_start = i;
            break;
        }
    }

    if (!node_addr) {
        printf("Error: No node specified. Use -node <ip:port>\n");
        return 1;
    }

    /* Parse node address */
    char host[256];
    uint16_t port = DEFAULT_RPC_PORT;
    strncpy(host, node_addr, sizeof(host) - 1);

    char* colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = (uint16_t)atoi(colon + 1);
    }

    /* Add initial node */
    add_node(host, port);

    if (!g_nodes[0].active) {
        printf("Error: Cannot connect to node %s:%d\n", host, port);
        return 1;
    }

    g_active_node = 0;
    printf("Connected to %s:%d (latency: %d ms)\n", host, port, g_nodes[0].latency_ms);

    /* Auto-discover additional nodes */
    if (auto_discover) {
        printf("Discovering peers...\n");
        discover_peers_from_node(0);

        int best = select_best_node();
        if (best >= 0 && best != g_active_node) {
            if (g_nodes[best].latency_ms < g_nodes[g_active_node].latency_ms - 20) {
                g_active_node = best;
                printf("Switched to faster node: %s:%d (%d ms)\n",
                       g_nodes[best].ip, g_nodes[best].port, g_nodes[best].latency_ms);
            }
        }
        printf("Found %d nodes total\n", g_node_count);
    }

    /* Execute command */
    if (cmd_start >= argc) {
        printf("Error: No command specified\n");
        return 1;
    }

    const char* cmd = argv[cmd_start];
    int ret = 0;

    if (strcmp(cmd, "info") == 0) {
        ret = cmd_info();
    }
    else if (strcmp(cmd, "balance") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Error: Missing address\n");
            return 1;
        }
        ret = cmd_balance(argv[cmd_start + 1]);
    }
    else if (strcmp(cmd, "listunspent") == 0) {
        if (cmd_start + 1 >= argc) {
            printf("Error: Missing address\n");
            return 1;
        }
        ret = cmd_listunspent(argv[cmd_start + 1]);
    }
    else if (strcmp(cmd, "send") == 0) {
        if (cmd_start + 4 >= argc) {
            printf("Error: Missing arguments\n");
            printf("Usage: send <privkey> <pubkey> <to_address> <amount> [fee]\n");
            return 1;
        }
        const char* privkey = argv[cmd_start + 1];
        const char* pubkey = argv[cmd_start + 2];
        const char* to_addr = argv[cmd_start + 3];
        double amount = strtod(argv[cmd_start + 4], NULL);
        double fee = 0.0001;
        if (cmd_start + 5 < argc) {
            fee = strtod(argv[cmd_start + 5], NULL);
        }
        ret = cmd_send(privkey, pubkey, to_addr, amount, fee);
    }
    else {
        printf("Error: Unknown command '%s'\n", cmd);
        ret = 1;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return ret;
}
