/**
 * FTC Address Generator
 *
 * Generates a new keypair and prints the address
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ftc.h"
#include "../src/crypto/keys.h"

int main(int argc, char** argv)
{
    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;

    /* Check if importing a private key */
    if (argc > 1 && strlen(argv[1]) == 64) {
        /* Import private key from hex */
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(argv[1] + i * 2, "%02x", &byte);
            privkey[i] = (uint8_t)byte;
        }
        /* Derive public key from private key */
        ftc_pubkey_from_privkey(privkey, pubkey);
    } else {
        /* Generate keypair */
        if (!ftc_keypair_generate(privkey, pubkey)) {
            fprintf(stderr, "Failed to generate keypair\n");
            return 1;
        }
    }

    /* Derive address */
    ftc_address_t addr;
    ftc_address_from_pubkey(pubkey, addr);

    /* Encode address */
    char addr_str[64];
    ftc_address_encode(addr, true, addr_str);  /* true = mainnet */

    /* Print private key in hex */
    printf("Private key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", privkey[i]);
    }
    printf("\n");

    /* Print public key in hex */
    printf("Public key:  ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pubkey[i]);
    }
    printf("\n");

    /* Print address */
    printf("Address:     %s\n", addr_str);

    return 0;
}
