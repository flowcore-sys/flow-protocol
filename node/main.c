/**
 * FTC Node Main Entry Point
 *
 * Usage: ftc-node [options]
 *
 * Options:
 *   -port <port>       P2P port (default: 17317)
 *   -rpcport <port>    RPC port (default: 17318)
 *   -datadir <dir>     Data directory (default: ftcdata)
 *   -testnet           Use testnet
 *   -seed <host>       Add seed node
 *   -bootstrap <url>   Download blocks.dat from URL
 *   -help              Show help
 */

#include "full_node.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#endif

/*==============================================================================
 * BOOTSTRAP DOWNLOAD
 *============================================================================*/

/* Parse URL into host, port, path */
static bool parse_url(const char* url, char* host, int* port, char* path)
{
    *port = 17318;  /* Default RPC port */

    /* Skip http:// */
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }

    /* Extract host */
    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        /* host:port/path */
        size_t host_len = colon - p;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        *port = atoi(colon + 1);
        if (slash) {
            strcpy(path, slash);
        } else {
            strcpy(path, "/blocks.dat");
        }
    } else if (slash) {
        /* host/path */
        size_t host_len = slash - p;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        strcpy(path, slash);
    } else {
        /* host only */
        strcpy(host, p);
        strcpy(path, "/blocks.dat");
    }

    return host[0] != '\0';
}

static bool download_blocks_dat(const char* url, const char* dest_path)
{
    char host[256] = {0};
    char path[256] = {0};
    int port = 17318;

    if (!parse_url(url, host, &port, path)) {
        printf("Invalid URL: %s\n", url);
        return false;
    }

    printf("Downloading blocks.dat from %s:%d%s...\n", host, port, path);

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* Resolve hostname */
    struct hostent* he = gethostbyname(host);
    if (!he) {
        printf("Failed to resolve hostname: %s\n", host);
        return false;
    }

    /* Create socket */
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#endif
        printf("Failed to create socket\n");
        return false;
    }

    /* Connect */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("Failed to connect to %s:%d\n", host, port);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    /* Send HTTP GET request */
    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);
    send(sock, request, (int)strlen(request), 0);

    /* Receive response */
    char buffer[65536];
    int total_header = 0;
    char* header_end = NULL;

    /* Read headers */
    while (!header_end && total_header < (int)sizeof(buffer) - 1) {
        int ret = recv(sock, buffer + total_header, (int)(sizeof(buffer) - 1 - total_header), 0);
        if (ret <= 0) break;
        total_header += ret;
        buffer[total_header] = '\0';
        header_end = strstr(buffer, "\r\n\r\n");
    }

    if (!header_end) {
        printf("Invalid HTTP response\n");
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    /* Check HTTP status */
    if (strstr(buffer, "200 OK") == NULL) {
        printf("HTTP error: %.50s\n", buffer);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    /* Get content length */
    long content_length = 0;
    char* cl = strstr(buffer, "Content-Length:");
    if (cl) {
        content_length = atol(cl + 15);
    }

    /* Open output file */
    FILE* f = fopen(dest_path, "wb");
    if (!f) {
        printf("Failed to create file: %s\n", dest_path);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    /* Write any body data already received */
    header_end += 4;  /* Skip \r\n\r\n */
    int body_in_buffer = total_header - (int)(header_end - buffer);
    if (body_in_buffer > 0) {
        fwrite(header_end, 1, body_in_buffer, f);
    }

    /* Stream rest of file */
    long received = body_in_buffer;
    int last_percent = 0;

    while (content_length == 0 || received < content_length) {
        int ret = recv(sock, buffer, sizeof(buffer), 0);
        if (ret <= 0) break;
        fwrite(buffer, 1, ret, f);
        received += ret;

        /* Show progress */
        if (content_length > 0) {
            int percent = (int)(received * 100 / content_length);
            if (percent != last_percent) {
                printf("\rDownloading: %d%% (%ld / %ld bytes)", percent, received, content_length);
                fflush(stdout);
                last_percent = percent;
            }
        }
    }
    printf("\n");

    fclose(f);
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    printf("Downloaded %ld bytes to %s\n", received, dest_path);
    return received > 0;
}

/*==============================================================================
 * MAIN
 *============================================================================*/

static void print_help(void)
{
    printf("FTC Central Server v%s\n", FTC_NODE_VERSION);
    printf("\n");
    printf("Usage: ftc-node [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -rpcport <port>    RPC port (default: 17318)\n");
    printf("  -stratum [port]    Enable Stratum pool server (default port: 3333)\n");
    printf("  -datadir <dir>     Data directory (default: ftcdata)\n");
    printf("  -addnode <ip:port> Add a peer to connect to (can use multiple times)\n");
    printf("  -peers <file>      Load peers from text file (one per line)\n");
    printf("  -testnet           Use testnet\n");
    printf("  -bootstrap <url>   Download blocks.dat from node URL\n");
    printf("  -nowallet          Disable wallet\n");
    printf("  -recover           Recovery mode: skip validation when loading blocks\n");
    printf("  -help              Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  ftc-node -addnode 15.164.228.225:17319\n");
    printf("  ftc-node -peers peers.txt\n");
    printf("  ftc-node -datadir /var/ftc -rpcport 17318\n");
    printf("\n");
}

int main(int argc, char* argv[])
{
    ftc_node_config_t config;
    ftc_node_config_default(&config);

    const char* bootstrap_url = NULL;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-rpcport") == 0 && i + 1 < argc) {
            config.rpc_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-stratum") == 0) {
            config.stratum_enabled = true;
            /* Check if next arg is a port number */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config.stratum_port = (uint16_t)atoi(argv[++i]);
            }
        }
        else if (strcmp(argv[i], "-datadir") == 0 && i + 1 < argc) {
            strncpy(config.data_dir, argv[++i], sizeof(config.data_dir) - 1);
        }
        else if (strcmp(argv[i], "-testnet") == 0) {
            config.testnet = true;
        }
        else if (strcmp(argv[i], "-bootstrap") == 0 && i + 1 < argc) {
            bootstrap_url = argv[++i];
        }
        else if (strcmp(argv[i], "-nowallet") == 0) {
            config.wallet_enabled = false;
        }
        else if (strcmp(argv[i], "-recover") == 0) {
            config.recovery_mode = true;
            printf("*** RECOVERY MODE: Loading blocks without validation ***\n");
        }
        else if (strcmp(argv[i], "-addnode") == 0 && i + 1 < argc) {
            if (config.connect_node_count < 16) {
                config.connect_nodes[config.connect_node_count++] = argv[++i];
            }
        }
        else if (strcmp(argv[i], "-peers") == 0 && i + 1 < argc) {
            /* Load peers from text file */
            const char* peers_file = argv[++i];
            FILE* f = fopen(peers_file, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f) && config.connect_node_count < 16) {
                    /* Remove newline */
                    char* nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    char* cr = strchr(line, '\r');
                    if (cr) *cr = '\0';
                    /* Skip empty lines and comments */
                    if (line[0] && line[0] != '#') {
                        config.connect_nodes[config.connect_node_count++] = strdup(line);
                    }
                }
                fclose(f);
                printf("Loaded %d peers from %s\n", config.connect_node_count, peers_file);
            } else {
                printf("Warning: Could not open peers file: %s\n", peers_file);
            }
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_help();
            return 1;
        }
    }

    /* Create data directory */
    mkdir(config.data_dir, 0755);

    /* Bootstrap: download blocks.dat from another node if requested */
    if (bootstrap_url) {
        char blocks_path[512];
        snprintf(blocks_path, sizeof(blocks_path), "%s/blocks.dat", config.data_dir);

        /* Check if blocks.dat already exists */
        FILE* existing = fopen(blocks_path, "rb");
        if (existing) {
            fclose(existing);
            printf("blocks.dat already exists, skipping bootstrap download\n");
            printf("Delete %s to force re-download\n", blocks_path);
        } else {
            if (!download_blocks_dat(bootstrap_url, blocks_path)) {
                printf("Bootstrap download failed\n");
            }
        }
    }

    /* Create and start node */
    ftc_node_t* node = ftc_node_new(&config);
    if (!node) {
        printf("Failed to create node\n");
        return 1;
    }

    if (!ftc_node_start(node)) {
        printf("Failed to start node\n");
        ftc_node_free(node);
        return 1;
    }

    /* Run main loop */
    ftc_node_run(node);

    /* Cleanup */
    ftc_node_free(node);

    return 0;
}
