/**
 * Ed25519 Digital Signatures
 *
 * Wrapper around TweetNaCl implementation
 */

#include "ed25519.h"
#include "tweetnacl.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
void randombytes(unsigned char *x, unsigned long long xlen) {
    BCryptGenRandom(NULL, x, (ULONG)xlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}
#else
#include <fcntl.h>
#include <unistd.h>
void randombytes(unsigned char *x, unsigned long long xlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, x, xlen);
        (void)n;  /* Ignore return - best effort randomness */
        close(fd);
    }
}
#endif

/* TweetNaCl internal types and functions */
typedef long long gf[16];

extern void scalarbase(gf p[4], const unsigned char *s);
extern void pack(unsigned char *r, gf p[4]);

void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    uint8_t d[64];
    gf p[4];

    /* Copy seed to sk */
    memcpy(sk, seed, 32);

    /* Hash seed with SHA-512 */
    crypto_hash(d, seed, 32);

    /* Clamp */
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    /* Compute public key: A = d * B */
    scalarbase(p, d);
    pack(pk, p);

    /* Copy pk to sk[32..63] */
    memcpy(sk + 32, pk, 32);
}

void ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t sk[64]) {
    unsigned long long siglen;
    uint8_t* sm = (uint8_t*)malloc(msg_len + 64);

    crypto_sign(sm, &siglen, msg, (unsigned long long)msg_len, sk);
    memcpy(sig, sm, 64);

    free(sm);
}

int ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t pk[32]) {
    unsigned long long mlen;
    uint8_t* sm = (uint8_t*)malloc(msg_len + 64);
    uint8_t* m = (uint8_t*)malloc(msg_len + 64);
    int result;

    /* Construct signed message: sig || msg */
    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msg_len);

    result = crypto_sign_open(m, &mlen, sm, (unsigned long long)(msg_len + 64), pk);

    free(sm);
    free(m);

    return result;
}
