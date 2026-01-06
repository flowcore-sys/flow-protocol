/**
 * FTC Genesis Block Miner
 *
 * Mines the genesis block and outputs the nonce and hash
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/ftc.h"
#include "../src/crypto/keccak256.h"
#include "../src/core/block.h"
#include "../src/core/tx.h"

/* Progress reporting interval */
#define PROGRESS_INTERVAL 1000000

int main(int argc, char** argv)
{
    printf("==============================================\n");
    printf("  FTC Genesis Block Miner\n");
    printf("==============================================\n\n");

    /* Create genesis block template */
    ftc_block_t* genesis = ftc_block_new();
    if (!genesis) {
        fprintf(stderr, "Failed to create genesis block\n");
        return 1;
    }

    /* Set header fields */
    genesis->header.version = 1;
    ftc_hash_zero(genesis->header.prev_hash);
    genesis->header.timestamp = FTC_GENESIS_TIMESTAMP;
    genesis->header.bits = FTC_GENESIS_BITS;
    genesis->header.nonce = 0;

    /* Create coinbase transaction */
    ftc_tx_t* coinbase = ftc_tx_create_coinbase(
        0,  /* Height 0 */
        FTC_INITIAL_REWARD,
        (const uint8_t*)FTC_GENESIS_MESSAGE,
        strlen(FTC_GENESIS_MESSAGE)
    );

    if (!coinbase) {
        fprintf(stderr, "Failed to create coinbase transaction\n");
        ftc_block_free(genesis);
        return 1;
    }

    if (!ftc_block_add_tx(genesis, coinbase)) {
        fprintf(stderr, "Failed to add coinbase to block\n");
        ftc_tx_free(coinbase);
        ftc_block_free(genesis);
        return 1;
    }

    /* Calculate Merkle root */
    ftc_block_update_merkle(genesis);

    /* Get target */
    ftc_hash256_t target;
    ftc_bits_to_target(FTC_GENESIS_BITS, target);

    printf("Genesis Parameters:\n");
    printf("  Timestamp:  %u (%s", FTC_GENESIS_TIMESTAMP, ctime((time_t*)&genesis->header.timestamp));
    printf("  Bits:       0x%08x\n", FTC_GENESIS_BITS);
    printf("  Message:    %s\n", FTC_GENESIS_MESSAGE);

    char merkle_hex[65];
    ftc_hash_to_hex(genesis->header.merkle_root, merkle_hex);
    printf("  Merkle:     %s\n", merkle_hex);

    char target_hex[65];
    ftc_hash_to_hex(target, target_hex);
    printf("  Target:     %s\n\n", target_hex);

    printf("Mining genesis block...\n\n");

    /* Mining loop */
    time_t start_time = time(NULL);
    uint64_t hashes = 0;
    ftc_hash256_t hash;

    for (uint32_t nonce = 0; ; nonce++) {
        genesis->header.nonce = nonce;

        /* Hash the header */
        ftc_hash_block_header(&genesis->header, hash);

        /* Check against target */
        if (ftc_hash_compare(hash, target) <= 0) {
            /* Found valid nonce! */
            time_t end_time = time(NULL);
            double elapsed = difftime(end_time, start_time);

            printf("\n==============================================\n");
            printf("  GENESIS BLOCK FOUND!\n");
            printf("==============================================\n\n");

            printf("Nonce:    %u (0x%08x)\n", nonce, nonce);

            char hash_hex[65];
            ftc_hash_to_hex(hash, hash_hex);
            printf("Hash:     %s\n", hash_hex);

            printf("\nStatistics:\n");
            printf("  Hashes:   %llu\n", (unsigned long long)hashes);
            printf("  Time:     %.0f seconds\n", elapsed);
            if (elapsed > 0) {
                printf("  Rate:     %.2f MH/s\n", hashes / elapsed / 1000000.0);
            }

            printf("\nC code for genesis block:\n");
            printf("---------------------------------------------\n");
            printf("#define GENESIS_NONCE_MAINNET   %uU\n\n", nonce);
            printf("static const uint8_t GENESIS_HASH[32] = {\n    ");
            for (int i = 0; i < 32; i++) {
                printf("0x%02x", hash[i]);
                if (i < 31) printf(", ");
                if (i == 15) printf("\n    ");
            }
            printf("\n};\n");
            printf("---------------------------------------------\n");

            ftc_block_free(genesis);
            return 0;
        }

        hashes++;

        /* Progress report */
        if (hashes % PROGRESS_INTERVAL == 0) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start_time);
            double rate = elapsed > 0 ? hashes / elapsed / 1000000.0 : 0;

            printf("\r  Hashes: %llu  |  Rate: %.2f MH/s  |  Nonce: 0x%08x",
                   (unsigned long long)hashes, rate, nonce);
            fflush(stdout);
        }

        /* Check for overflow */
        if (nonce == UINT32_MAX) {
            printf("\n\nExhausted nonce space without finding valid hash!\n");
            printf("Try a different timestamp or message.\n");
            ftc_block_free(genesis);
            return 1;
        }
    }
}
