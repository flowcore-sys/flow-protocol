/**
 * FTC Keccak-256 Implementation
 *
 * Based on NIST SHA-3 (FIPS 202)
 * Keccak-256: r=1088, c=512, output=256 bits
 */

#include "keccak256.h"
#include <string.h>
#include <stdio.h>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

/* Keccak-256 parameters */
#define KECCAK_RATE     136     /* (1600 - 512) / 8 = 136 bytes */
#define KECCAK_ROUNDS   24

/* Round constants */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets */
static const int ROTC[24] = {
    1,  3,  6,  10, 15, 21, 28, 36,
    45, 55, 2,  14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
};

/* Pi permutation */
static const int PILN[24] = {
    10, 7,  11, 17, 18, 3,  5,  16,
    8,  21, 24, 4,  15, 23, 19, 13,
    12, 2,  20, 14, 22, 9,  6,  1
};

/*==============================================================================
 * HELPER MACROS
 *============================================================================*/

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/*==============================================================================
 * KECCAK-F[1600] PERMUTATION
 *============================================================================*/

static void keccak_f1600(uint64_t state[25])
{
    uint64_t t, bc[5];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step */
        for (int i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                    state[i + 15] ^ state[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        /* Rho and Pi steps */
        t = state[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            bc[0] = state[j];
            state[j] = ROTL64(t, ROTC[i]);
            t = bc[0];
        }

        /* Chi step */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota step */
        state[0] ^= RC[round];
    }
}

/*==============================================================================
 * STREAMING API
 *============================================================================*/

void ftc_keccak_init(ftc_keccak_ctx_t* ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
}

void ftc_keccak_update(ftc_keccak_ctx_t* ctx, const uint8_t* data, size_t len)
{
    size_t i = 0;

    /* Process buffered data first */
    if (ctx->buffer_len > 0) {
        size_t to_copy = KECCAK_RATE - ctx->buffer_len;
        if (to_copy > len) to_copy = len;

        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        i += to_copy;

        if (ctx->buffer_len == KECCAK_RATE) {
            /* XOR buffer into state */
            for (size_t j = 0; j < KECCAK_RATE / 8; j++) {
                ctx->state[j] ^= ((uint64_t*)ctx->buffer)[j];
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }

    /* Process full blocks */
    while (i + KECCAK_RATE <= len) {
        for (size_t j = 0; j < KECCAK_RATE / 8; j++) {
            uint64_t word;
            memcpy(&word, data + i + j * 8, 8);
            ctx->state[j] ^= word;
        }
        keccak_f1600(ctx->state);
        i += KECCAK_RATE;
    }

    /* Buffer remaining data */
    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
        ctx->buffer_len = len - i;
    }
}

void ftc_keccak_final(ftc_keccak_ctx_t* ctx, ftc_hash256_t out)
{
    /* Pad message: 0x01 ... 0x80 */
    ctx->buffer[ctx->buffer_len] = 0x01;  /* Keccak padding (not SHA-3's 0x06) */
    memset(ctx->buffer + ctx->buffer_len + 1, 0, KECCAK_RATE - ctx->buffer_len - 1);
    ctx->buffer[KECCAK_RATE - 1] |= 0x80;

    /* XOR final block */
    for (size_t i = 0; i < KECCAK_RATE / 8; i++) {
        uint64_t word;
        memcpy(&word, ctx->buffer + i * 8, 8);
        ctx->state[i] ^= word;
    }
    keccak_f1600(ctx->state);

    /* Extract 256 bits */
    memcpy(out, ctx->state, 32);
}

/*==============================================================================
 * BASIC HASHING
 *============================================================================*/

void ftc_keccak256(const uint8_t* data, size_t len, ftc_hash256_t out)
{
    ftc_keccak_ctx_t ctx;
    ftc_keccak_init(&ctx);
    ftc_keccak_update(&ctx, data, len);
    ftc_keccak_final(&ctx, out);
}

void ftc_keccak256_double(const uint8_t* data, size_t len, ftc_hash256_t out)
{
    ftc_hash256_t first;
    ftc_keccak256(data, len, first);
    ftc_keccak256(first, 32, out);
}

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

void ftc_hash_block_header(const ftc_block_header_t* header, ftc_hash256_t out)
{
    ftc_keccak256_double((const uint8_t*)header, sizeof(ftc_block_header_t), out);
}

int ftc_hash_compare(const ftc_hash256_t a, const ftc_hash256_t b)
{
    /* Compare as big-endian (MSB first) */
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

bool ftc_hash_is_zero(const ftc_hash256_t hash)
{
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) return false;
    }
    return true;
}

void ftc_hash_zero(ftc_hash256_t hash)
{
    memset(hash, 0, 32);
}

void ftc_hash_copy(ftc_hash256_t dst, const ftc_hash256_t src)
{
    memcpy(dst, src, 32);
}

void ftc_hash_to_hex(const ftc_hash256_t hash, char* hex)
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = digits[(hash[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

bool ftc_hex_to_hash(const char* hex, ftc_hash256_t hash)
{
    if (strlen(hex) != 64) return false;

    for (int i = 0; i < 32; i++) {
        int hi = hex[i * 2];
        int lo = hex[i * 2 + 1];

        if (hi >= '0' && hi <= '9') hi = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
        else return false;

        if (lo >= '0' && lo <= '9') lo = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
        else return false;

        hash[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

void ftc_hash_reverse(const ftc_hash256_t in, ftc_hash256_t out)
{
    for (int i = 0; i < 32; i++) {
        out[i] = in[31 - i];
    }
}
