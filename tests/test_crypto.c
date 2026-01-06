/**
 * FTC Crypto Tests
 *
 * Test Keccak-256, Ed25519, and address generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ftc.h"
#include "../src/crypto/keccak256.h"
#include "../src/crypto/keys.h"
#include "../src/crypto/merkle.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", name); \
    tests_run++; \
} while(0)

#define PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while(0)

/*==============================================================================
 * KECCAK-256 TESTS
 *============================================================================*/

static void test_keccak256_empty(void)
{
    TEST("Keccak-256 empty string");

    /* Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 */
    const uint8_t expected[32] = {
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };

    ftc_hash256_t hash;
    ftc_keccak256((const uint8_t*)"", 0, hash);

    if (memcmp(hash, expected, 32) == 0) {
        PASS();
    } else {
        FAIL("hash mismatch");
        char hex[65];
        ftc_hash_to_hex(hash, hex);
        printf("    Got: %s\n", hex);
    }
}

static void test_keccak256_abc(void)
{
    TEST("Keccak-256 'abc'");

    /* Keccak-256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45 */
    const uint8_t expected[32] = {
        0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f,
        0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
        0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36,
        0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45
    };

    ftc_hash256_t hash;
    ftc_keccak256((const uint8_t*)"abc", 3, hash);

    if (memcmp(hash, expected, 32) == 0) {
        PASS();
    } else {
        FAIL("hash mismatch");
        char hex[65];
        ftc_hash_to_hex(hash, hex);
        printf("    Got: %s\n", hex);
    }
}

static void test_keccak256_long(void)
{
    TEST("Keccak-256 long message");

    /* Keccak-256("The quick brown fox jumps over the lazy dog") */
    const char* msg = "The quick brown fox jumps over the lazy dog";
    const uint8_t expected[32] = {
        0x4d, 0x74, 0x1b, 0x6f, 0x1e, 0xb2, 0x9c, 0xb2,
        0xa9, 0xb9, 0x91, 0x1c, 0x82, 0xf5, 0x6f, 0xa8,
        0xd7, 0x3b, 0x04, 0x95, 0x9d, 0x3d, 0x9d, 0x22,
        0x28, 0x95, 0xdf, 0x6c, 0x0b, 0x28, 0xaa, 0x15
    };

    ftc_hash256_t hash;
    ftc_keccak256((const uint8_t*)msg, strlen(msg), hash);

    if (memcmp(hash, expected, 32) == 0) {
        PASS();
    } else {
        FAIL("hash mismatch");
        char hex[65];
        ftc_hash_to_hex(hash, hex);
        printf("    Got: %s\n", hex);
    }
}

static void test_double_keccak(void)
{
    TEST("Double Keccak-256");

    ftc_hash256_t single, double_hash;
    ftc_keccak256((const uint8_t*)"test", 4, single);
    ftc_keccak256(single, 32, double_hash);

    ftc_hash256_t direct;
    ftc_keccak256_double((const uint8_t*)"test", 4, direct);

    if (memcmp(double_hash, direct, 32) == 0) {
        PASS();
    } else {
        FAIL("double hash mismatch");
    }
}

/*==============================================================================
 * KEY GENERATION TESTS
 *============================================================================*/

static void test_keypair_generation(void)
{
    TEST("Keypair generation");

    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;

    if (!ftc_keypair_generate(privkey, pubkey)) {
        FAIL("generation failed");
        return;
    }

    /* Verify we can derive the same public key */
    ftc_pubkey_t derived;
    ftc_pubkey_from_privkey(privkey, derived);

    if (memcmp(pubkey, derived, 32) == 0) {
        PASS();
    } else {
        FAIL("pubkey derivation mismatch");
    }
}

static void test_signing(void)
{
    TEST("Ed25519 signing and verification");

    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;
    ftc_keypair_generate(privkey, pubkey);

    const uint8_t message[] = "Test message for FTC";
    ftc_signature_t signature;

    ftc_sign(privkey, pubkey, message, sizeof(message), signature);

    if (ftc_verify(pubkey, message, sizeof(message), signature)) {
        PASS();
    } else {
        FAIL("signature verification failed");
    }
}

static void test_invalid_signature(void)
{
    TEST("Invalid signature rejection");

    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;
    ftc_keypair_generate(privkey, pubkey);

    const uint8_t message[] = "Test message";
    ftc_signature_t signature;
    ftc_sign(privkey, pubkey, message, sizeof(message), signature);

    /* Modify message */
    uint8_t bad_message[] = "Test massage";  /* 'message' -> 'massage' */

    if (!ftc_verify(pubkey, bad_message, sizeof(bad_message), signature)) {
        PASS();
    } else {
        FAIL("accepted invalid signature");
    }
}

/*==============================================================================
 * ADDRESS TESTS
 *============================================================================*/

static void test_address_derivation(void)
{
    TEST("Address derivation");

    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;
    ftc_keypair_generate(privkey, pubkey);

    ftc_address_t address;
    ftc_address_from_pubkey(pubkey, address);

    /* Address should be non-zero */
    int nonzero = 0;
    for (int i = 0; i < 20; i++) {
        if (address[i] != 0) nonzero++;
    }

    if (nonzero > 0) {
        PASS();
    } else {
        FAIL("address is all zeros");
    }
}

static void test_address_encoding(void)
{
    TEST("Address Base58 encoding/decoding");

    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;
    ftc_keypair_generate(privkey, pubkey);

    ftc_address_t address;
    ftc_address_from_pubkey(pubkey, address);

    char encoded[64];
    int len = ftc_address_encode(address, true, encoded);

    if (len <= 0) {
        FAIL("encoding failed");
        return;
    }

    ftc_address_t decoded;
    bool mainnet;
    if (!ftc_address_decode(encoded, decoded, &mainnet)) {
        FAIL("decoding failed");
        return;
    }

    if (memcmp(address, decoded, 20) == 0 && mainnet) {
        PASS();
    } else {
        FAIL("roundtrip mismatch");
    }
}

/*==============================================================================
 * MERKLE TREE TESTS
 *============================================================================*/

static void test_merkle_single(void)
{
    TEST("Merkle root single transaction");

    ftc_hash256_t tx_hash = {1, 2, 3, 4, 5, 6, 7, 8};
    ftc_hash256_t root;

    ftc_merkle_root(&tx_hash, 1, root);

    /* Single TX: root = tx_hash */
    if (memcmp(root, tx_hash, 32) == 0) {
        PASS();
    } else {
        FAIL("single tx merkle mismatch");
    }
}

static void test_merkle_two(void)
{
    TEST("Merkle root two transactions");

    ftc_hash256_t tx_hashes[2] = {
        {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
        {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
         16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
    };

    ftc_hash256_t root;
    ftc_merkle_root(tx_hashes, 2, root);

    /* Verify by manual calculation */
    uint8_t concat[64];
    memcpy(concat, tx_hashes[0], 32);
    memcpy(concat + 32, tx_hashes[1], 32);

    ftc_hash256_t expected;
    ftc_keccak256(concat, 64, expected);

    if (memcmp(root, expected, 32) == 0) {
        PASS();
    } else {
        FAIL("two tx merkle mismatch");
    }
}

/*==============================================================================
 * MAIN
 *============================================================================*/

int main(void)
{
    printf("==============================================\n");
    printf("  FTC Crypto Tests\n");
    printf("==============================================\n\n");

    printf("Keccak-256:\n");
    test_keccak256_empty();
    test_keccak256_abc();
    test_keccak256_long();
    test_double_keccak();

    printf("\nKey Generation:\n");
    test_keypair_generation();
    test_signing();
    test_invalid_signature();

    printf("\nAddresses:\n");
    test_address_derivation();
    test_address_encoding();

    printf("\nMerkle Tree:\n");
    test_merkle_single();
    test_merkle_two();

    printf("\n==============================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("==============================================\n");

    return tests_passed == tests_run ? 0 : 1;
}
