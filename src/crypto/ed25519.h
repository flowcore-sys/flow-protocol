/**
 * Ed25519 Digital Signatures
 *
 * Based on TweetNaCl - a compact, audited implementation
 * Public domain
 */

#ifndef FTC_ED25519_H
#define FTC_ED25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate Ed25519 keypair from seed
 *
 * @param pk Output: public key (32 bytes)
 * @param sk Output: secret key (64 bytes = seed + public key)
 * @param seed Input: 32 bytes of random data
 */
void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

/**
 * Sign message
 *
 * @param sig Output: signature (64 bytes)
 * @param msg Message to sign
 * @param msg_len Message length
 * @param sk Secret key (64 bytes)
 */
void ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t sk[64]);

/**
 * Verify signature
 *
 * @param sig Signature (64 bytes)
 * @param msg Message
 * @param msg_len Message length
 * @param pk Public key (32 bytes)
 * @return 0 if valid, -1 if invalid
 */
int ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t msg_len, const uint8_t pk[32]);

#ifdef __cplusplus
}
#endif

#endif /* FTC_ED25519_H */
