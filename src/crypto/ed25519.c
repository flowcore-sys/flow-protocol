/**
 * Ed25519 Digital Signatures
 *
 * Clean implementation based on RFC 8032 and ref10
 */

#include "ed25519.h"
#include <string.h>
#include <stdlib.h>

/*==============================================================================
 * SHA-512 (required for Ed25519)
 *============================================================================*/

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define S1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define s0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define s1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static uint64_t load64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void store64_be(uint8_t* p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8); p[7] = (uint8_t)x;
}

static void sha512_block(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80], a, b, c, d, e, f, g, hh, t1, t2;
    int i;

    for (i = 0; i < 16; i++) w[i] = load64_be(block + i * 8);
    for (i = 16; i < 80; i++) w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 80; i++) {
        t1 = hh + S1(e) + CH(e, f, g) + K512[i] + w[i];
        t2 = S0(a) + MAJ(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512(uint8_t hash[64], const uint8_t* msg, size_t len) {
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    size_t i, blocks = len / 128;

    for (i = 0; i < blocks; i++) sha512_block(h, msg + i * 128);

    size_t rem = len % 128;
    memset(block, 0, 128);
    memcpy(block, msg + blocks * 128, rem);
    block[rem] = 0x80;

    if (rem >= 112) {
        sha512_block(h, block);
        memset(block, 0, 128);
    }

    uint64_t bits = len * 8;
    store64_be(block + 120, bits);
    sha512_block(h, block);

    for (i = 0; i < 8; i++) store64_be(hash + i * 8, h[i]);
}

/*==============================================================================
 * FIELD ARITHMETIC (mod p = 2^255 - 19)
 *============================================================================*/

typedef int64_t fe[16];  /* Field element: 16 limbs of 16 bits */

static const fe D = {
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
};

static const fe D2 = {
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199
};

static const fe SQRTM1 = {
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
};

static void fe_0(fe h) { int i; for (i = 0; i < 16; i++) h[i] = 0; }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }

static void fe_copy(fe h, const fe f) {
    int i; for (i = 0; i < 16; i++) h[i] = f[i];
}

static void fe_add(fe h, const fe f, const fe g) {
    int i; for (i = 0; i < 16; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    int i; for (i = 0; i < 16; i++) h[i] = f[i] - g[i];
}

static void fe_neg(fe h, const fe f) {
    int i; for (i = 0; i < 16; i++) h[i] = -f[i];
}

static void fe_reduce(fe h) {
    int64_t c;
    int i;
    for (i = 0; i < 16; i++) {
        c = h[i] >> 16;
        h[i] -= c << 16;
        if (i < 15) h[i+1] += c;
        else h[0] += c * 38;
    }
    c = h[0] >> 16;
    h[0] -= c << 16;
    h[1] += c;
}

static void fe_mul(fe h, const fe f, const fe g) {
    int64_t t[31] = {0};
    int i, j;

    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += f[i] * g[j];

    for (i = 16; i < 31; i++) t[i - 16] += t[i] * 38;

    for (i = 0; i < 16; i++) h[i] = t[i];
    fe_reduce(h);
    fe_reduce(h);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1); for (i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1); for (i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

static void fe_pow22523(fe out, const fe z) {
    fe t0, t1, t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0); for (i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0); for (i = 0; i < 9; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1); for (i = 0; i < 19; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1); for (i = 0; i < 9; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0); for (i = 0; i < 49; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1); for (i = 0; i < 99; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1); for (i = 0; i < 49; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0); fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

static int fe_isneg(const fe f) {
    uint8_t s[32];
    fe t;
    fe_copy(t, f);
    fe_reduce(t);
    fe_reduce(t);

    int64_t c = 0;
    for (int i = 0; i < 16; i++) {
        c += t[i];
        s[2*i] = (uint8_t)c;
        s[2*i+1] = (uint8_t)(c >> 8);
        c >>= 16;
    }
    return s[0] & 1;
}

static int fe_isnonzero(const fe f) {
    uint8_t s[32];
    fe t;
    fe_copy(t, f);
    fe_reduce(t);
    fe_reduce(t);

    int64_t c = 0;
    for (int i = 0; i < 16; i++) {
        c += t[i];
        s[2*i] = (uint8_t)c;
        s[2*i+1] = (uint8_t)(c >> 8);
        c >>= 16;
    }

    uint8_t r = 0;
    for (int i = 0; i < 32; i++) r |= s[i];
    return r != 0;
}

static void fe_frombytes(fe h, const uint8_t s[32]) {
    int i;
    for (i = 0; i < 16; i++) h[i] = (int64_t)s[2*i] + ((int64_t)s[2*i+1] << 8);
    h[15] &= 0x7fff;
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    fe t;
    fe_copy(t, h);
    fe_reduce(t);
    fe_reduce(t);

    /* Reduce mod p */
    int64_t c = (t[0] + 19) >> 16;
    for (int i = 1; i < 15; i++) c = (t[i] + c) >> 16;
    c = (t[15] + c - 0x8000) >> 16;

    t[0] += 19 * c;
    for (int i = 0; i < 15; i++) {
        t[i+1] += t[i] >> 16;
        t[i] &= 0xffff;
    }
    t[15] &= 0x7fff;

    for (int i = 0; i < 16; i++) {
        s[2*i] = (uint8_t)t[i];
        s[2*i+1] = (uint8_t)(t[i] >> 8);
    }
}

/*==============================================================================
 * GROUP OPERATIONS (Extended coordinates)
 *============================================================================*/

typedef struct {
    fe X, Y, Z, T;
} ge;

static void ge_0(ge* p) {
    fe_0(p->X);
    fe_1(p->Y);
    fe_1(p->Z);
    fe_0(p->T);
}

static int ge_frombytes(ge* p, const uint8_t s[32]) {
    fe u, v, v3, vxx, check;

    fe_frombytes(p->Y, s);
    fe_1(p->Z);
    fe_sq(u, p->Y);          /* u = y^2 */
    fe_mul(v, u, D);         /* v = dy^2 */
    fe_sub(u, u, p->Z);      /* u = y^2 - 1 */
    fe_add(v, v, p->Z);      /* v = dy^2 + 1 */

    fe_sq(v3, v);
    fe_mul(v3, v3, v);       /* v3 = v^3 */
    fe_sq(p->X, v3);
    fe_mul(p->X, p->X, v);
    fe_mul(p->X, p->X, u);   /* x = uv^7 */

    fe_pow22523(p->X, p->X); /* x = (uv^7)^((q-5)/8) */
    fe_mul(p->X, p->X, v3);
    fe_mul(p->X, p->X, u);   /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(vxx, p->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u);
        if (fe_isnonzero(check)) return -1;
        fe_mul(p->X, p->X, SQRTM1);
    }

    if (fe_isneg(p->X) != (s[31] >> 7)) fe_neg(p->X, p->X);

    fe_mul(p->T, p->X, p->Y);
    return 0;
}

static void ge_tobytes(uint8_t s[32], const ge* p) {
    fe x, y, z_inv;

    fe_invert(z_inv, p->Z);
    fe_mul(x, p->X, z_inv);
    fe_mul(y, p->Y, z_inv);
    fe_tobytes(s, y);
    s[31] ^= fe_isneg(x) << 7;
}

static void ge_add(ge* r, const ge* p, const ge* q) {
    fe a, b, c, d, e, f, g, h, t;

    fe_sub(a, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(a, a, t);
    fe_add(b, p->X, p->Y);
    fe_add(t, q->X, q->Y);
    fe_mul(b, b, t);
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, D2);
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);

    fe_mul(r->X, e, f);
    fe_mul(r->Y, h, g);
    fe_mul(r->Z, g, f);
    fe_mul(r->T, e, h);
}

static void ge_double(ge* r, const ge* p) {
    fe a, b, c, d, e, f, g, h;

    fe_sq(a, p->X);
    fe_sq(b, p->Y);
    fe_sq(c, p->Z); fe_add(c, c, c);
    fe_add(d, a, b);
    fe_add(e, p->X, p->Y); fe_sq(e, e); fe_sub(e, e, d);
    fe_sub(g, a, b);
    fe_sub(f, c, g);
    fe_neg(h, d);

    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->Z, f, g);
    fe_mul(r->T, e, h);
}

static void ge_scalarmult_base(ge* r, const uint8_t s[32]) {
    /* Base point */
    static const uint8_t B[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    };

    ge bp, t;
    ge_frombytes(&bp, B);
    ge_0(r);

    for (int i = 255; i >= 0; i--) {
        ge_double(&t, r);
        if ((s[i / 8] >> (i % 8)) & 1) {
            ge_add(r, &t, &bp);
        } else {
            *r = t;
        }
    }
}

static void ge_scalarmult(ge* r, const uint8_t s[32], const ge* p) {
    ge t;
    ge_0(r);

    for (int i = 255; i >= 0; i--) {
        ge_double(&t, r);
        if ((s[i / 8] >> (i % 8)) & 1) {
            ge_add(r, &t, p);
        } else {
            *r = t;
        }
    }
}

/*==============================================================================
 * SCALAR OPERATIONS (mod L)
 *============================================================================*/

static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void sc_reduce(uint8_t s[64]) {
    int64_t t[64];
    int i, j;

    for (i = 0; i < 64; i++) t[i] = s[i];

    for (i = 63; i >= 32; i--) {
        int64_t carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            t[j] += carry - t[i] * (int64_t)L[j - (i - 32)];
            carry = (t[j] + 128) >> 8;
            t[j] -= carry << 8;
        }
        t[j] += carry;
        t[i] = 0;
    }

    int64_t carry = 0;
    for (i = 0; i < 32; i++) {
        t[i] += carry - (t[31] >> 4) * (int64_t)L[i];
        carry = t[i] >> 8;
        t[i] &= 0xff;
    }

    for (i = 0; i < 32; i++) t[i] -= carry * (int64_t)L[i];

    for (i = 0; i < 32; i++) {
        t[i + 1] += t[i] >> 8;
        s[i] = (uint8_t)t[i];
    }
}

static void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) {
    int64_t t[64] = {0};
    int i, j;

    for (i = 0; i < 32; i++)
        for (j = 0; j < 32; j++)
            t[i + j] += (int64_t)a[i] * (int64_t)b[j];

    for (i = 0; i < 32; i++) t[i] += c[i];

    for (i = 0; i < 64; i++) {
        t[i + 1] += t[i] >> 8;
        t[i] &= 0xff;
    }

    uint8_t r[64];
    for (i = 0; i < 64; i++) r[i] = (uint8_t)t[i];
    sc_reduce(r);
    memcpy(s, r, 32);
}

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    uint8_t h[64];
    ge A;

    sha512(h, seed, 32);
    h[0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    ge_scalarmult_base(&A, h);
    ge_tobytes(pk, &A);

    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);
}

void ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t sk[64]) {
    uint8_t h[64], r[64], hram[64];
    ge R;
    size_t buf_len = 64 + msg_len;
    uint8_t* buf = (uint8_t*)malloc(buf_len);

    sha512(h, sk, 32);
    h[0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    /* r = H(h[32..64] || msg) */
    memcpy(buf, h + 32, 32);
    memcpy(buf + 32, msg, msg_len);
    sha512(r, buf, 32 + msg_len);
    sc_reduce(r);

    /* R = r * B */
    ge_scalarmult_base(&R, r);
    ge_tobytes(sig, &R);

    /* H(R || pk || msg) */
    memcpy(buf, sig, 32);
    memcpy(buf + 32, sk + 32, 32);
    memcpy(buf + 64, msg, msg_len);
    sha512(hram, buf, 64 + msg_len);
    sc_reduce(hram);

    /* s = r + H(R || pk || msg) * a */
    sc_muladd(sig + 32, hram, h, r);

    free(buf);
}

int ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t pk[32]) {
    ge A, R, sB, hA;
    uint8_t hram[64], check[32];
    size_t buf_len = 64 + msg_len;
    uint8_t* buf = (uint8_t*)malloc(buf_len);

    if (ge_frombytes(&A, pk) != 0) { free(buf); return -1; }
    if (sig[63] & 0xe0) { free(buf); return -1; }

    /* H(R || pk || msg) */
    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    memcpy(buf + 64, msg, msg_len);
    sha512(hram, buf, 64 + msg_len);
    sc_reduce(hram);

    /* sB = s * B */
    ge_scalarmult_base(&sB, sig + 32);

    /* hA = h * A (need to negate A for subtraction) */
    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);
    ge_scalarmult(&hA, hram, &A);

    /* R + hA = sB? */
    if (ge_frombytes(&R, sig) != 0) { free(buf); return -1; }
    ge_add(&hA, &R, &hA);
    ge_tobytes(check, &hA);

    free(buf);

    /* Compare sB with R + hA */
    ge_tobytes(buf = malloc(32), &sB);
    int result = memcmp(buf, check, 32) == 0 ? 0 : -1;
    free(buf);
    return result;
}
