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
 *   -help              Show help
 */

#include "full_node.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/stat.h>
#endif

static void print_help(void)
{
    printf("FTC Node v%s\n", FTC_NODE_VERSION);
    printf("\n");
    printf("Usage: ftc-node [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -port <port>       P2P port (default: 17317)\n");
    printf("  -rpcport <port>    RPC port (default: 17318)\n");
    printf("  -datadir <dir>     Data directory (default: ftcdata)\n");
    printf("  -testnet           Use testnet\n");
    printf("  -seed <host>       Add seed node\n");
    printf("  -nowallet          Disable wallet\n");
    printf("  -help              Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  ftc-node -datadir /var/ftc -seed seed.flowprotocol.net\n");
    printf("\n");
}

#define MAX_CUSTOM_SEEDS 16

int main(int argc, char* argv[])
{
    ftc_node_config_t config;
    ftc_node_config_default(&config);

    /* Default seeds */
    static const char* default_seeds[] = {
        "seed.flowprotocol.net",
        "seed1.flowprotocol.net",
        "seed2.flowprotocol.net",
    };

    /* Custom seeds storage */
    static const char* custom_seeds[MAX_CUSTOM_SEEDS];
    int custom_seed_count = 0;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
            config.p2p_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-rpcport") == 0 && i + 1 < argc) {
            config.rpc_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-datadir") == 0 && i + 1 < argc) {
            strncpy(config.data_dir, argv[++i], sizeof(config.data_dir) - 1);
        }
        else if (strcmp(argv[i], "-testnet") == 0) {
            config.testnet = true;
        }
        else if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc) {
            if (custom_seed_count < MAX_CUSTOM_SEEDS) {
                custom_seeds[custom_seed_count++] = argv[++i];
            } else {
                printf("Warning: too many seeds, ignoring %s\n", argv[++i]);
            }
        }
        else if (strcmp(argv[i], "-nowallet") == 0) {
            config.wallet_enabled = false;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_help();
            return 1;
        }
    }

    /* Use custom seeds if provided, otherwise use defaults */
    if (custom_seed_count > 0) {
        config.seeds = custom_seeds;
        config.seed_count = custom_seed_count;
    } else {
        config.seeds = default_seeds;
        config.seed_count = 3;
    }

    /* Create data directory */
    mkdir(config.data_dir, 0755);

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
