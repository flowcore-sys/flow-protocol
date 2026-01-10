/**
 * FTC Node Main Entry Point
 *
 * Usage: ftc-node [options]
 *
 * Options:
 *   -rpcport <port>    RPC port (default: 17318)
 *   -stratum [port]    Enable Stratum pool server (default: 3333)
 *   -datadir <dir>     Data directory (default: ftcdata)
 *   -addnode <ip:port> Add peer to connect to
 *   -peers <file>      Load peers from file
 *   -bootstrap <url>   Download blocks.dat from URL
 *   -genaddress        Generate new wallet address
 *   -nowallet          Disable wallet
 *   -recover           Recovery mode
 *   -help              Show help
 */

#include "full_node.h"
#include "../src/wallet/wallet.h"
#include "../src/crypto/keys.h"
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

    /* Stream rest of file with visual progress */
    long received = body_in_buffer;
    int last_percent = -1;
    time_t start_time = time(NULL);

    printf("\n");
    while (content_length == 0 || received < content_length) {
        int ret = recv(sock, buffer, sizeof(buffer), 0);
        if (ret <= 0) break;
        fwrite(buffer, 1, ret, f);
        received += ret;

        /* Show visual progress bar */
        if (content_length > 0) {
            int percent = (int)(received * 100 / content_length);
            if (percent != last_percent) {
                /* Calculate speed */
                time_t elapsed = time(NULL) - start_time;
                double speed = (elapsed > 0) ? (received / 1024.0 / 1024.0) / elapsed : 0;

                /* Progress bar */
                int bar_width = 40;
                int filled = (percent * bar_width) / 100;

                printf("\r  [");
                for (int i = 0; i < bar_width; i++) {
                    if (i < filled) printf("=");
                    else if (i == filled) printf(">");
                    else printf(" ");
                }
                printf("] %3d%% %.1f/%.1f MB (%.2f MB/s)",
                       percent,
                       received / 1024.0 / 1024.0,
                       content_length / 1024.0 / 1024.0,
                       speed);
                fflush(stdout);
                last_percent = percent;
            }
        } else {
            /* Unknown size - just show received */
            printf("\r  Downloading: %.2f MB...", received / 1024.0 / 1024.0);
            fflush(stdout);
        }
    }
    printf("\n\n");

    fclose(f);
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    printf("  Bootstrap complete: %.2f MB downloaded\n", received / 1024.0 / 1024.0);
    return received > 0;
}

/*==============================================================================
 * WALLET GENERATION
 *============================================================================*/

static int generate_address(const char* data_dir)
{
    /* Ensure data directory exists */
    mkdir(data_dir, 0755);

    char wallet_path[512];
    snprintf(wallet_path, sizeof(wallet_path), "%s/wallet.dat", data_dir);

    /* Check if wallet already exists */
    ftc_wallet_t* wallet = ftc_wallet_load(wallet_path);
    if (wallet) {
        printf("Wallet already exists at %s\n", wallet_path);
        printf("Existing addresses:\n\n");

        for (int i = 0; i < wallet->key_count; i++) {
            char addr_str[64];
            ftc_address_encode(wallet->keys[i].address, true, addr_str);
            printf("  Address %d: %s\n", i + 1, addr_str);
        }

        printf("\nGenerating new address...\n\n");
    } else {
        wallet = ftc_wallet_new();
        if (!wallet) {
            printf("Failed to create wallet\n");
            return 1;
        }
        printf("Creating new wallet at %s\n\n", wallet_path);
    }

    /* Generate new key */
    ftc_wallet_key_t* key = ftc_wallet_new_key(wallet, "Generated");
    if (!key) {
        printf("Failed to generate key\n");
        ftc_wallet_free(wallet);
        return 1;
    }

    /* Get address string */
    char addr_str[64];
    ftc_address_encode(key->address, true, addr_str);

    /* Get WIF private key */
    char wif[64];
    ftc_privkey_to_wif(key->privkey, true, wif);

    /* Save wallet */
    if (!ftc_wallet_save(wallet, wallet_path)) {
        printf("Warning: Failed to save wallet\n");
    }

    printf("=== New FTC Address Generated ===\n\n");
    printf("  Address:     %s\n", addr_str);
    printf("  Private Key: %s\n\n", wif);
    printf("IMPORTANT: Save your private key! It cannot be recovered.\n");
    printf("Wallet saved to: %s\n\n", wallet_path);

    ftc_wallet_free(wallet);
    return 0;
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
    printf("  -bootstrap <url>   Download blocks.dat from node URL\n");
    printf("  -genaddress        Generate new wallet address and exit\n");
    printf("  -nowallet          Disable wallet\n");
    printf("  -recover           Recovery mode: skip validation when loading blocks\n");
    printf("  -help              Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  ftc-node -addnode 15.164.228.225:17317\n");
    printf("  ftc-node -bootstrap http://15.164.228.225:17318/blocks.dat\n");
    printf("  ftc-node -datadir /var/ftc -stratum\n");
    printf("  ftc-node -genaddress\n");
    printf("\n");
}

int main(int argc, char* argv[])
{
    ftc_node_config_t config;
    ftc_node_config_default(&config);

    const char* bootstrap_url = NULL;
    bool do_genaddress = false;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-genaddress") == 0) {
            do_genaddress = true;
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

    /* Generate address and exit if requested */
    if (do_genaddress) {
        return generate_address(config.data_dir);
    }

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
