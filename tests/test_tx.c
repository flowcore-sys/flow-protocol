/**
 * FTC Transaction Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ftc.h"
#include "../src/core/tx.h"
#include "../src/crypto/keccak256.h"
#include "../src/crypto/keys.h"

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

static void test_tx_creation(void)
{
    TEST("Transaction creation");

    ftc_tx_t* tx = ftc_tx_new();
    if (!tx) {
        FAIL("allocation failed");
        return;
    }

    if (tx->version == 1 && tx->input_count == 0 && tx->output_count == 0) {
        PASS();
    } else {
        FAIL("unexpected initial state");
    }

    ftc_tx_free(tx);
}

static void test_coinbase_creation(void)
{
    TEST("Coinbase transaction");

    ftc_tx_t* cb = ftc_tx_create_coinbase(0, 50 * FTC_COIN, (const uint8_t*)"FTC", 3);
    if (!cb) {
        FAIL("creation failed");
        return;
    }

    if (!ftc_tx_is_coinbase(cb)) {
        FAIL("not recognized as coinbase");
        ftc_tx_free(cb);
        return;
    }

    if (cb->output_count == 1 && cb->outputs[0].value == 50 * FTC_COIN) {
        PASS();
    } else {
        FAIL("wrong output");
    }

    ftc_tx_free(cb);
}

static void test_add_input_output(void)
{
    TEST("Add inputs and outputs");

    ftc_tx_t* tx = ftc_tx_new();

    ftc_hash256_t prev_txid = {0x01, 0x02, 0x03};
    if (!ftc_tx_add_input(tx, prev_txid, 0)) {
        FAIL("add input failed");
        ftc_tx_free(tx);
        return;
    }

    ftc_address_t address = {0x0a, 0x0b, 0x0c};
    if (!ftc_tx_add_output(tx, 1000000, address)) {
        FAIL("add output failed");
        ftc_tx_free(tx);
        return;
    }

    if (tx->input_count == 1 && tx->output_count == 1 &&
        tx->outputs[0].value == 1000000) {
        PASS();
    } else {
        FAIL("counts mismatch");
    }

    ftc_tx_free(tx);
}

static void test_tx_serialization(void)
{
    TEST("Transaction serialization");

    ftc_tx_t* tx = ftc_tx_create_coinbase(100, 25 * FTC_COIN, NULL, 0);
    if (!tx) {
        FAIL("creation failed");
        return;
    }

    /* Serialize */
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    if (size == 0) {
        FAIL("size calculation failed");
        ftc_tx_free(tx);
        return;
    }

    uint8_t* data = malloc(size);
    if (ftc_tx_serialize(tx, data, size) != size) {
        FAIL("serialization failed");
        free(data);
        ftc_tx_free(tx);
        return;
    }

    /* Deserialize */
    size_t consumed;
    ftc_tx_t* restored = ftc_tx_deserialize(data, size, &consumed);
    free(data);

    if (!restored) {
        FAIL("deserialization failed");
        ftc_tx_free(tx);
        return;
    }

    /* Compare */
    if (tx->version == restored->version &&
        tx->input_count == restored->input_count &&
        tx->output_count == restored->output_count &&
        tx->locktime == restored->locktime &&
        consumed == size) {
        PASS();
    } else {
        FAIL("roundtrip mismatch");
    }

    ftc_tx_free(tx);
    ftc_tx_free(restored);
}

static void test_tx_hash(void)
{
    TEST("Transaction hash");

    ftc_tx_t* tx1 = ftc_tx_create_coinbase(0, 50 * FTC_COIN, NULL, 0);
    ftc_tx_t* tx2 = ftc_tx_create_coinbase(1, 50 * FTC_COIN, NULL, 0);

    ftc_hash256_t hash1, hash2;
    ftc_tx_hash(tx1, hash1);
    ftc_tx_hash(tx2, hash2);

    /* Different txs should have different hashes */
    if (memcmp(hash1, hash2, 32) != 0) {
        PASS();
    } else {
        FAIL("identical hashes for different txs");
    }

    ftc_tx_free(tx1);
    ftc_tx_free(tx2);
}

static void test_tx_signing(void)
{
    TEST("Transaction signing");

    /* Create keypair */
    ftc_privkey_t privkey;
    ftc_pubkey_t pubkey;
    ftc_keypair_generate(privkey, pubkey);

    /* Create transaction */
    ftc_tx_t* tx = ftc_tx_new();

    ftc_hash256_t prev_txid = {0x11, 0x22, 0x33};
    ftc_tx_add_input(tx, prev_txid, 0);

    ftc_address_t address;
    ftc_address_from_pubkey(pubkey, address);
    ftc_tx_add_output(tx, 1000000, address);

    /* Sign */
    if (!ftc_tx_sign_input(tx, 0, privkey, pubkey)) {
        FAIL("signing failed");
        ftc_tx_free(tx);
        return;
    }

    /* Verify */
    if (ftc_tx_verify_input(tx, 0)) {
        PASS();
    } else {
        FAIL("verification failed");
    }

    ftc_tx_free(tx);
}

static void test_tx_output_value(void)
{
    TEST("Transaction output value");

    ftc_tx_t* tx = ftc_tx_new();

    ftc_address_t addr = {0};
    ftc_tx_add_output(tx, 100000000, addr);
    ftc_tx_add_output(tx, 50000000, addr);
    ftc_tx_add_output(tx, 25000000, addr);

    uint64_t total = ftc_tx_output_value(tx);

    if (total == 175000000) {
        PASS();
    } else {
        FAIL("wrong total");
        printf("    Expected: 175000000, Got: %llu\n", (unsigned long long)total);
    }

    ftc_tx_free(tx);
}

static void test_tx_hex_conversion(void)
{
    TEST("Transaction hex conversion");

    ftc_tx_t* tx = ftc_tx_create_coinbase(999, 50 * FTC_COIN, (const uint8_t*)"test", 4);
    if (!tx) {
        FAIL("creation failed");
        return;
    }

    char* hex = ftc_tx_to_hex(tx);
    if (!hex) {
        FAIL("to_hex failed");
        ftc_tx_free(tx);
        return;
    }

    ftc_tx_t* restored = ftc_tx_from_hex(hex);
    free(hex);

    if (!restored) {
        FAIL("from_hex failed");
        ftc_tx_free(tx);
        return;
    }

    ftc_hash256_t hash1, hash2;
    ftc_tx_hash(tx, hash1);
    ftc_tx_hash(restored, hash2);

    if (memcmp(hash1, hash2, 32) == 0) {
        PASS();
    } else {
        FAIL("hash mismatch after hex roundtrip");
    }

    ftc_tx_free(tx);
    ftc_tx_free(restored);
}

int main(void)
{
    printf("==============================================\n");
    printf("  FTC Transaction Tests\n");
    printf("==============================================\n\n");

    printf("Creation:\n");
    test_tx_creation();
    test_coinbase_creation();
    test_add_input_output();

    printf("\nSerialization:\n");
    test_tx_serialization();
    test_tx_hex_conversion();

    printf("\nHashing:\n");
    test_tx_hash();

    printf("\nSigning:\n");
    test_tx_signing();

    printf("\nValues:\n");
    test_tx_output_value();

    printf("\n==============================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("==============================================\n");

    return tests_passed == tests_run ? 0 : 1;
}
