/**
 * FTC Key Management
 *
 * Ed25519 keypair generation, signing, and address derivation
 */

#ifndef FTC_KEYS_H
#define FTC_KEYS_H

#include "../include/ftc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * KEYPAIR GENERATION
 *============================================================================*/

/**
 * Generate random Ed25519 keypair
 * Returns false if random generation fails
 */
bool ftc_keypair_generate(ftc_privkey_t privkey, ftc_pubkey_t pubkey);

/**
 * Derive public key from private key
 */
void ftc_pubkey_from_privkey(const ftc_privkey_t privkey, ftc_pubkey_t pubkey);

/**
 * Validate public key (is on curve)
 */
bool ftc_pubkey_validate(const ftc_pubkey_t pubkey);

/*==============================================================================
 * ADDRESS DERIVATION
 *============================================================================*/

/**
 * Derive address (pubkey_hash) from public key
 * address = Keccak256(pubkey)[0:20]
 */
void ftc_address_from_pubkey(const ftc_pubkey_t pubkey, ftc_address_t address);

/**
 * Encode address as Base58Check string
 * Buffer must be at least 35 bytes
 * Returns actual string length
 */
int ftc_address_encode(const ftc_address_t address, bool mainnet, char* str);

/**
 * Decode Base58Check address
 * Returns false if invalid
 */
bool ftc_address_decode(const char* str, ftc_address_t address, bool* mainnet);

/**
 * Validate address checksum
 */
bool ftc_address_validate(const char* str);

/*==============================================================================
 * SIGNING & VERIFICATION
 *============================================================================*/

/**
 * Sign message with private key (Ed25519)
 */
void ftc_sign(
    const ftc_privkey_t privkey,
    const ftc_pubkey_t pubkey,
    const uint8_t* message,
    size_t msg_len,
    ftc_signature_t signature
);

/**
 * Verify signature
 * Returns true if valid
 */
bool ftc_verify(
    const ftc_pubkey_t pubkey,
    const uint8_t* message,
    size_t msg_len,
    const ftc_signature_t signature
);

/*==============================================================================
 * WIF (WALLET IMPORT FORMAT)
 *============================================================================*/

/**
 * Export private key as WIF string
 * Buffer must be at least 52 bytes
 */
int ftc_privkey_to_wif(const ftc_privkey_t privkey, bool mainnet, char* wif);

/**
 * Import private key from WIF string
 */
bool ftc_privkey_from_wif(const char* wif, ftc_privkey_t privkey, bool* mainnet);

/*==============================================================================
 * BASE58 ENCODING
 *============================================================================*/

/**
 * Base58 encode
 * Returns output length, 0 on error
 */
size_t ftc_base58_encode(const uint8_t* data, size_t len, char* out, size_t out_len);

/**
 * Base58 decode
 * Returns output length, 0 on error
 */
size_t ftc_base58_decode(const char* str, uint8_t* out, size_t out_len);

/**
 * Base58Check encode (with version byte and checksum)
 */
size_t ftc_base58check_encode(uint8_t version, const uint8_t* data, size_t len,
                               char* out, size_t out_len);

/**
 * Base58Check decode (verifies checksum)
 */
size_t ftc_base58check_decode(const char* str, uint8_t* version,
                               uint8_t* out, size_t out_len);

/*==============================================================================
 * RANDOM NUMBER GENERATION
 *============================================================================*/

/**
 * Generate cryptographically secure random bytes
 */
bool ftc_random_bytes(uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FTC_KEYS_H */
