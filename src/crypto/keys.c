/**
 * FTC Key Management Implementation
 *
 * Uses clean Ed25519 implementation
 */

#include "keys.h"
#include "ed25519.h"
#include "keccak256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/*==============================================================================
 * RANDOM NUMBER GENERATION
 *============================================================================*/

bool ftc_random_bytes(uint8_t* buf, size_t len)
{
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;

    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t r = read(fd, buf + read_bytes, len - read_bytes);
        if (r <= 0) {
            close(fd);
            return false;
        }
        read_bytes += r;
    }
    close(fd);
    return true;
#endif
}

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

bool ftc_keypair_generate(ftc_privkey_t privkey, ftc_pubkey_t pubkey)
{
    if (!ftc_random_bytes(privkey, 32)) {
        return false;
    }
    ftc_pubkey_from_privkey(privkey, pubkey);
    return true;
}

void ftc_pubkey_from_privkey(const ftc_privkey_t privkey, ftc_pubkey_t pubkey)
{
    uint8_t sk[64];
    ed25519_create_keypair(pubkey, sk, privkey);
}

bool ftc_pubkey_validate(const ftc_pubkey_t pubkey)
{
    /* Basic validation: check high bit of last byte */
    /* Full validation would decode the point */
    return (pubkey[31] & 0x80) == 0 || (pubkey[31] & 0x80) != 0;  /* Always true for now */
}

void ftc_address_from_pubkey(const ftc_pubkey_t pubkey, ftc_address_t address)
{
    ftc_hash256_t hash;
    ftc_keccak256(pubkey, 32, hash);
    memcpy(address, hash, 20);
}

void ftc_sign(
    const ftc_privkey_t privkey,
    const ftc_pubkey_t pubkey,
    const uint8_t* message,
    size_t msg_len,
    ftc_signature_t signature
)
{
    uint8_t sk[64];
    memcpy(sk, privkey, 32);
    memcpy(sk + 32, pubkey, 32);
    ed25519_sign(signature, message, msg_len, sk);
}

bool ftc_verify(
    const ftc_pubkey_t pubkey,
    const uint8_t* message,
    size_t msg_len,
    const ftc_signature_t signature
)
{
    return ed25519_verify(signature, message, msg_len, pubkey) == 0;
}

/*==============================================================================
 * BASE58 ENCODING
 *============================================================================*/

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

size_t ftc_base58_encode(const uint8_t* data, size_t len, char* out, size_t out_len)
{
    /* Count leading zeros */
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    /* Allocate enough space for base58 conversion */
    size_t size = (len - zeros) * 138 / 100 + 1;
    uint8_t* buf = (uint8_t*)calloc(size, 1);

    for (size_t i = zeros; i < len; i++) {
        int carry = data[i];
        for (size_t j = 0; j < size; j++) {
            carry += 256 * buf[size - 1 - j];
            buf[size - 1 - j] = carry % 58;
            carry /= 58;
        }
    }

    /* Skip leading zeros in buffer */
    size_t idx = 0;
    while (idx < size && buf[idx] == 0) idx++;

    /* Check output size */
    size_t result_len = zeros + (size - idx);
    if (result_len >= out_len) {
        free(buf);
        return 0;
    }

    /* Output */
    size_t pos = 0;
    for (size_t i = 0; i < zeros; i++) out[pos++] = '1';
    while (idx < size) out[pos++] = BASE58_ALPHABET[buf[idx++]];
    out[pos] = '\0';

    free(buf);
    return pos;
}

size_t ftc_base58_decode(const char* str, uint8_t* out, size_t out_len)
{
    size_t str_len = strlen(str);

    /* Count leading '1's */
    size_t zeros = 0;
    while (zeros < str_len && str[zeros] == '1') zeros++;

    /* Allocate conversion buffer */
    size_t size = str_len * 733 / 1000 + 1;
    uint8_t* buf = (uint8_t*)calloc(size, 1);

    for (size_t i = zeros; i < str_len; i++) {
        /* Find character in alphabet */
        const char* p = strchr(BASE58_ALPHABET, str[i]);
        if (!p) {
            free(buf);
            return 0;
        }
        int carry = (int)(p - BASE58_ALPHABET);

        for (size_t j = 0; j < size; j++) {
            carry += 58 * buf[size - 1 - j];
            buf[size - 1 - j] = carry & 0xff;
            carry >>= 8;
        }
    }

    /* Skip leading zeros in buffer */
    size_t idx = 0;
    while (idx < size && buf[idx] == 0) idx++;

    /* Check output size */
    size_t result_len = zeros + (size - idx);
    if (result_len > out_len) {
        free(buf);
        return 0;
    }

    /* Output */
    memset(out, 0, zeros);
    memcpy(out + zeros, buf + idx, size - idx);

    free(buf);
    return result_len;
}

size_t ftc_base58check_encode(uint8_t version, const uint8_t* data, size_t len,
                               char* out, size_t out_len)
{
    /* Build: version + data + checksum */
    size_t total = 1 + len + 4;
    uint8_t* buf = (uint8_t*)malloc(total);

    buf[0] = version;
    memcpy(buf + 1, data, len);

    /* Double Keccak checksum */
    ftc_hash256_t hash1, hash2;
    ftc_keccak256(buf, 1 + len, hash1);
    ftc_keccak256(hash1, 32, hash2);
    memcpy(buf + 1 + len, hash2, 4);

    size_t result = ftc_base58_encode(buf, total, out, out_len);
    free(buf);
    return result;
}

size_t ftc_base58check_decode(const char* str, uint8_t* version,
                               uint8_t* out, size_t out_len)
{
    uint8_t buf[128];
    size_t len = ftc_base58_decode(str, buf, sizeof(buf));

    if (len < 5) return 0;  /* version + data + checksum */

    /* Verify checksum */
    ftc_hash256_t hash1, hash2;
    ftc_keccak256(buf, len - 4, hash1);
    ftc_keccak256(hash1, 32, hash2);

    if (memcmp(hash2, buf + len - 4, 4) != 0) return 0;

    /* Extract version and data */
    *version = buf[0];

    size_t data_len = len - 5;
    if (data_len > out_len) return 0;

    memcpy(out, buf + 1, data_len);
    return data_len;
}

/*==============================================================================
 * ADDRESS ENCODING
 *============================================================================*/

int ftc_address_encode(const ftc_address_t address, bool mainnet, char* str)
{
    uint8_t version = mainnet ? FTC_PUBKEY_ADDRESS : FTC_TESTNET_PUBKEY;
    return (int)ftc_base58check_encode(version, address, 20, str, 64);
}

bool ftc_address_decode(const char* str, ftc_address_t address, bool* mainnet)
{
    uint8_t version;
    size_t len = ftc_base58check_decode(str, &version, address, 20);

    if (len != 20) return false;

    if (version == FTC_PUBKEY_ADDRESS) {
        if (mainnet) *mainnet = true;
        return true;
    } else if (version == FTC_TESTNET_PUBKEY) {
        if (mainnet) *mainnet = false;
        return true;
    }

    return false;
}

bool ftc_address_validate(const char* str)
{
    ftc_address_t addr;
    bool mainnet;
    return ftc_address_decode(str, addr, &mainnet);
}

/*==============================================================================
 * WIF ENCODING
 *============================================================================*/

int ftc_privkey_to_wif(const ftc_privkey_t privkey, bool mainnet, char* wif)
{
    uint8_t version = mainnet ? FTC_PRIVKEY_PREFIX : (FTC_PRIVKEY_PREFIX + FTC_TESTNET_PUBKEY);
    return (int)ftc_base58check_encode(version, privkey, 32, wif, 64);
}

bool ftc_privkey_from_wif(const char* wif, ftc_privkey_t privkey, bool* mainnet)
{
    uint8_t version;
    uint8_t data[33];
    size_t len = ftc_base58check_decode(wif, &version, data, 33);

    if (len != 32 && len != 33) return false;

    memcpy(privkey, data, 32);

    if (version == FTC_PRIVKEY_PREFIX) {
        if (mainnet) *mainnet = true;
        return true;
    } else if (version == FTC_PRIVKEY_PREFIX + FTC_TESTNET_PUBKEY) {
        if (mainnet) *mainnet = false;
        return true;
    }

    return false;
}
