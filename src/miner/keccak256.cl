/**
 * FTC OpenCL Keccak-256 Mining Kernel
 *
 * High-performance GPU mining for AMD/Intel cards.
 * Implements double Keccak-256 for FTC Proof of Work.
 */

/*==============================================================================
 * KECCAK CONSTANTS
 *============================================================================*/

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

/*==============================================================================
 * HELPER MACROS
 *============================================================================*/

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/*==============================================================================
 * KECCAK-F[1600] PERMUTATION
 *============================================================================*/

void keccak_f1600(ulong* state)
{
    ulong t, bc[5];

    #pragma unroll
    for (int round = 0; round < 24; round++) {
        /* Theta */
        bc[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        bc[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        bc[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        bc[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        bc[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        t = bc[4] ^ ROTL64(bc[1], 1);
        state[0] ^= t; state[5] ^= t; state[10] ^= t; state[15] ^= t; state[20] ^= t;
        t = bc[0] ^ ROTL64(bc[2], 1);
        state[1] ^= t; state[6] ^= t; state[11] ^= t; state[16] ^= t; state[21] ^= t;
        t = bc[1] ^ ROTL64(bc[3], 1);
        state[2] ^= t; state[7] ^= t; state[12] ^= t; state[17] ^= t; state[22] ^= t;
        t = bc[2] ^ ROTL64(bc[4], 1);
        state[3] ^= t; state[8] ^= t; state[13] ^= t; state[18] ^= t; state[23] ^= t;
        t = bc[3] ^ ROTL64(bc[0], 1);
        state[4] ^= t; state[9] ^= t; state[14] ^= t; state[19] ^= t; state[24] ^= t;

        /* Rho + Pi */
        t = state[1];
        state[1]  = ROTL64(state[6], 44);
        state[6]  = ROTL64(state[9], 20);
        state[9]  = ROTL64(state[22], 61);
        state[22] = ROTL64(state[14], 39);
        state[14] = ROTL64(state[20], 18);
        state[20] = ROTL64(state[2], 62);
        state[2]  = ROTL64(state[12], 43);
        state[12] = ROTL64(state[13], 25);
        state[13] = ROTL64(state[19], 8);
        state[19] = ROTL64(state[23], 56);
        state[23] = ROTL64(state[15], 41);
        state[15] = ROTL64(state[4], 27);
        state[4]  = ROTL64(state[24], 14);
        state[24] = ROTL64(state[21], 2);
        state[21] = ROTL64(state[8], 55);
        state[8]  = ROTL64(state[16], 45);
        state[16] = ROTL64(state[5], 36);
        state[5]  = ROTL64(state[3], 28);
        state[3]  = ROTL64(state[18], 21);
        state[18] = ROTL64(state[17], 15);
        state[17] = ROTL64(state[11], 10);
        state[11] = ROTL64(state[7], 6);
        state[7]  = ROTL64(state[10], 3);
        state[10] = ROTL64(t, 1);

        /* Chi */
        bc[0] = state[0]; bc[1] = state[1]; bc[2] = state[2]; bc[3] = state[3]; bc[4] = state[4];
        state[0] ^= (~bc[1]) & bc[2];
        state[1] ^= (~bc[2]) & bc[3];
        state[2] ^= (~bc[3]) & bc[4];
        state[3] ^= (~bc[4]) & bc[0];
        state[4] ^= (~bc[0]) & bc[1];

        bc[0] = state[5]; bc[1] = state[6]; bc[2] = state[7]; bc[3] = state[8]; bc[4] = state[9];
        state[5] ^= (~bc[1]) & bc[2];
        state[6] ^= (~bc[2]) & bc[3];
        state[7] ^= (~bc[3]) & bc[4];
        state[8] ^= (~bc[4]) & bc[0];
        state[9] ^= (~bc[0]) & bc[1];

        bc[0] = state[10]; bc[1] = state[11]; bc[2] = state[12]; bc[3] = state[13]; bc[4] = state[14];
        state[10] ^= (~bc[1]) & bc[2];
        state[11] ^= (~bc[2]) & bc[3];
        state[12] ^= (~bc[3]) & bc[4];
        state[13] ^= (~bc[4]) & bc[0];
        state[14] ^= (~bc[0]) & bc[1];

        bc[0] = state[15]; bc[1] = state[16]; bc[2] = state[17]; bc[3] = state[18]; bc[4] = state[19];
        state[15] ^= (~bc[1]) & bc[2];
        state[16] ^= (~bc[2]) & bc[3];
        state[17] ^= (~bc[3]) & bc[4];
        state[18] ^= (~bc[4]) & bc[0];
        state[19] ^= (~bc[0]) & bc[1];

        bc[0] = state[20]; bc[1] = state[21]; bc[2] = state[22]; bc[3] = state[23]; bc[4] = state[24];
        state[20] ^= (~bc[1]) & bc[2];
        state[21] ^= (~bc[2]) & bc[3];
        state[22] ^= (~bc[3]) & bc[4];
        state[23] ^= (~bc[4]) & bc[0];
        state[24] ^= (~bc[0]) & bc[1];

        /* Iota */
        state[0] ^= RC[round];
    }
}

/*==============================================================================
 * KECCAK-256 HASH (80-byte input)
 *============================================================================*/

void keccak256_80(__private const uchar* data, __private uchar* hash)
{
    ulong state[25] = {0};

    /* Absorb 80 bytes (rate = 136 bytes) */
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        state[i] = ((__private const ulong*)data)[i];
    }

    /* Padding: 0x01 at byte 80, 0x80 at byte 135 */
    state[10] ^= 0x01UL;
    state[16] ^= 0x8000000000000000UL;

    keccak_f1600(state);

    /* Extract 256 bits */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        ((__private ulong*)hash)[i] = state[i];
    }
}

/*==============================================================================
 * KECCAK-256 HASH (32-byte input)
 *============================================================================*/

void keccak256_32(__private const uchar* data, __private uchar* hash)
{
    ulong state[25] = {0};

    /* Absorb 32 bytes */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        state[i] = ((__private const ulong*)data)[i];
    }

    /* Padding: 0x01 at byte 32, 0x80 at byte 135 */
    state[4] ^= 0x01UL;
    state[16] ^= 0x8000000000000000UL;

    keccak_f1600(state);

    /* Extract 256 bits */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        ((__private ulong*)hash)[i] = state[i];
    }
}

/*==============================================================================
 * DOUBLE KECCAK-256 MINING KERNEL
 *============================================================================*/

__kernel void keccak256_mine(
    __global const ulong* header64,     /* 80-byte header as 10 ulong (nonce at bytes 76-79) */
    __global const uchar* target,       /* 32-byte target */
    const uint nonce_start,
    __global uint* result_nonce,
    __global uchar* result_hash,
    __global uint* found
)
{
    uint gid = get_global_id(0);
    uint nonce = nonce_start + gid;

    /* Load header using 64-bit operations for alignment (like CUDA) */
    ulong local_header_u64[10];
    #pragma unroll
    for (int i = 0; i < 9; i++) {
        local_header_u64[i] = header64[i];
    }

    /* Set nonce in last 64-bit word (bytes 72-79, nonce is at 76-79) */
    /* header64[9] contains bytes 72-79, we need to replace bytes 76-79 with nonce */
    ulong last_word = header64[9];
    last_word = (last_word & 0x00000000FFFFFFFFUL) | ((ulong)nonce << 32);
    local_header_u64[9] = last_word;

    /* Double Keccak-256 - use aligned arrays for correct ulong casts */
    ulong hash1_u64[4], hash2_u64[4];
    keccak256_80((__private uchar*)local_header_u64, (__private uchar*)hash1_u64);
    keccak256_32((__private uchar*)hash1_u64, (__private uchar*)hash2_u64);
    __private uchar* hash2 = (__private uchar*)hash2_u64;

    /* Compare with target (big-endian comparison from MSB) */
    bool valid = true;
    #pragma unroll
    for (int i = 31; i >= 0; i--) {
        if (hash2[i] < target[i]) break;
        if (hash2[i] > target[i]) { valid = false; break; }
    }

    if (valid) {
        if (atomic_cmpxchg(found, 0, 1) == 0) {
            *result_nonce = nonce;
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                result_hash[i] = hash2[i];
            }
        }
    }
}
