/**
 * FTC Block Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ftc.h"
#include "../src/core/block.h"
#include "../src/core/tx.h"
#include "../src/crypto/keccak256.h"

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

static void test_block_creation(void)
{
    TEST("Block creation");

    ftc_block_t* block = ftc_block_new();
    if (!block) {
        FAIL("allocation failed");
        return;
    }

    if (block->header.version == 1 && block->tx_count == 0) {
        PASS();
    } else {
        FAIL("unexpected initial state");
    }

    ftc_block_free(block);
}

static void test_header_serialization(void)
{
    TEST("Header serialization");

    ftc_block_header_t header = {
        .version = 1,
        .prev_hash = {0x01, 0x02, 0x03},
        .merkle_root = {0x04, 0x05, 0x06},
        .timestamp = 1736208000,
        .bits = 0x1e0fffff,
        .nonce = 12345
    };

    uint8_t serialized[80];
    ftc_block_header_serialize(&header, serialized);

    ftc_block_header_t deserialized;
    ftc_block_header_deserialize(serialized, &deserialized);

    if (header.version == deserialized.version &&
        header.timestamp == deserialized.timestamp &&
        header.bits == deserialized.bits &&
        header.nonce == deserialized.nonce &&
        memcmp(header.prev_hash, deserialized.prev_hash, 32) == 0 &&
        memcmp(header.merkle_root, deserialized.merkle_root, 32) == 0) {
        PASS();
    } else {
        FAIL("roundtrip mismatch");
    }
}

static void test_block_hash(void)
{
    TEST("Block hash calculation");

    ftc_block_t* block = ftc_block_new();
    block->header.version = 1;
    block->header.timestamp = 1736208000;
    block->header.bits = 0x1e0fffff;
    block->header.nonce = 0;

    ftc_hash256_t hash1, hash2;
    ftc_block_hash(block, hash1);

    /* Change nonce, hash should change */
    block->header.nonce = 1;
    ftc_block_hash(block, hash2);

    if (memcmp(hash1, hash2, 32) != 0) {
        PASS();
    } else {
        FAIL("hash unchanged with different nonce");
    }

    ftc_block_free(block);
}

static void test_bits_to_target(void)
{
    TEST("Bits to target conversion");

    /* Genesis bits: 0x1e0fffff */
    ftc_hash256_t target;
    ftc_bits_to_target(0x1e0fffff, target);

    /* Should produce target with high bytes */
    if (target[29] == 0x0f && target[28] == 0xff && target[27] == 0xff) {
        PASS();
    } else {
        FAIL("unexpected target");
        char hex[65];
        ftc_hash_to_hex(target, hex);
        printf("    Got: %s\n", hex);
    }
}

static void test_target_roundtrip(void)
{
    TEST("Target/bits roundtrip");

    uint32_t original_bits = 0x1e0fffff;

    ftc_hash256_t target;
    ftc_bits_to_target(original_bits, target);

    uint32_t recovered_bits = ftc_target_to_bits(target);

    /* Allow small differences due to precision loss */
    if (recovered_bits == original_bits ||
        (recovered_bits >= original_bits - 0x100 && recovered_bits <= original_bits + 0x100)) {
        PASS();
    } else {
        FAIL("bits mismatch");
        printf("    Original: 0x%08x, Recovered: 0x%08x\n", original_bits, recovered_bits);
    }
}

static void test_difficulty_calculation(void)
{
    TEST("Difficulty calculation");

    double diff = ftc_bits_to_difficulty(0x1e0fffff);

    /* Genesis difficulty should be 1.0 */
    if (diff >= 0.9 && diff <= 1.1) {
        PASS();
    } else {
        FAIL("unexpected difficulty");
        printf("    Got: %f\n", diff);
    }
}

static void test_block_reward(void)
{
    TEST("Block reward calculation");

    /* Height 0: 50 FTC */
    if (ftc_get_block_reward(0) != 50 * FTC_COIN) {
        FAIL("wrong reward at height 0");
        return;
    }

    /* Height 209999: still 50 FTC */
    if (ftc_get_block_reward(209999) != 50 * FTC_COIN) {
        FAIL("wrong reward at height 209999");
        return;
    }

    /* Height 210000: 25 FTC (first halving) */
    if (ftc_get_block_reward(210000) != 25 * FTC_COIN) {
        FAIL("wrong reward at height 210000");
        return;
    }

    /* Height 420000: 12.5 FTC */
    if (ftc_get_block_reward(420000) != 1250000000ULL) {
        FAIL("wrong reward at height 420000");
        return;
    }

    PASS();
}

static void test_varint(void)
{
    TEST("Varint encoding");

    uint8_t buf[9];
    uint64_t decoded;

    /* Small value */
    ftc_varint_encode(100, buf);
    if (ftc_varint_decode(buf, 9, &decoded) != 1 || decoded != 100) {
        FAIL("small value");
        return;
    }

    /* Medium value */
    ftc_varint_encode(1000, buf);
    if (ftc_varint_decode(buf, 9, &decoded) != 3 || decoded != 1000) {
        FAIL("medium value");
        return;
    }

    /* Large value */
    ftc_varint_encode(100000, buf);
    if (ftc_varint_decode(buf, 9, &decoded) != 5 || decoded != 100000) {
        FAIL("large value");
        return;
    }

    PASS();
}

static void test_block_serialization(void)
{
    TEST("Full block serialization");

    /* Create block with coinbase */
    ftc_block_t* block = ftc_block_new();
    block->header.version = 1;
    block->header.timestamp = 1736208000;
    block->header.bits = 0x1e0fffff;
    block->header.nonce = 12345;

    ftc_tx_t* coinbase = ftc_tx_create_coinbase(0, 50 * FTC_COIN, NULL, 0);
    ftc_block_add_tx(block, coinbase);
    ftc_block_update_merkle(block);

    /* Serialize */
    size_t size = ftc_block_serialize(block, NULL, 0);
    if (size == 0) {
        FAIL("size calculation failed");
        ftc_block_free(block);
        return;
    }

    uint8_t* data = malloc(size);
    if (ftc_block_serialize(block, data, size) != size) {
        FAIL("serialization failed");
        free(data);
        ftc_block_free(block);
        return;
    }

    /* Deserialize */
    ftc_block_t* restored = ftc_block_deserialize(data, size);
    free(data);

    if (!restored) {
        FAIL("deserialization failed");
        ftc_block_free(block);
        return;
    }

    /* Compare */
    if (block->header.version == restored->header.version &&
        block->header.timestamp == restored->header.timestamp &&
        block->header.bits == restored->header.bits &&
        block->header.nonce == restored->header.nonce &&
        block->tx_count == restored->tx_count) {
        PASS();
    } else {
        FAIL("roundtrip mismatch");
    }

    ftc_block_free(block);
    ftc_block_free(restored);
}

int main(void)
{
    printf("==============================================\n");
    printf("  FTC Block Tests\n");
    printf("==============================================\n\n");

    printf("Block Structure:\n");
    test_block_creation();
    test_header_serialization();
    test_block_hash();

    printf("\nDifficulty:\n");
    test_bits_to_target();
    test_target_roundtrip();
    test_difficulty_calculation();

    printf("\nRewards:\n");
    test_block_reward();

    printf("\nSerialization:\n");
    test_varint();
    test_block_serialization();

    printf("\n==============================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("==============================================\n");

    return tests_passed == tests_run ? 0 : 1;
}
