/**
 * FTC P2P Protocol Messages
 *
 * Message format and types for peer communication
 */

#ifndef FTC_PROTOCOL_H
#define FTC_PROTOCOL_H

#include "../include/ftc.h"
#include "../core/block.h"
#include "../core/tx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * PROTOCOL CONSTANTS
 *============================================================================*/

#define FTC_PROTOCOL_MAGIC      0x46544300  /* "FTC\0" */
#define FTC_MAX_MESSAGE_SIZE    (4 * 1024 * 1024)  /* 4MB */
#define FTC_MAX_INV_COUNT       50000
#define FTC_MAX_ADDR_COUNT      1000
#define FTC_MAX_HEADERS_COUNT   2000
#define FTC_USER_AGENT          "/FTC:1.0.0/"

/*==============================================================================
 * MESSAGE TYPES
 *============================================================================*/

typedef enum {
    FTC_MSG_VERSION     = 1,    /* Handshake */
    FTC_MSG_VERACK      = 2,    /* Handshake acknowledgement */
    FTC_MSG_PING        = 3,    /* Keepalive */
    FTC_MSG_PONG        = 4,    /* Keepalive response */
    FTC_MSG_GETADDR     = 5,    /* Request peer addresses */
    FTC_MSG_ADDR        = 6,    /* Peer addresses */
    FTC_MSG_INV         = 7,    /* Inventory announcement */
    FTC_MSG_GETDATA     = 8,    /* Request data */
    FTC_MSG_NOTFOUND    = 9,    /* Data not found */
    FTC_MSG_BLOCK       = 10,   /* Block data */
    FTC_MSG_TX          = 11,   /* Transaction data */
    FTC_MSG_GETBLOCKS   = 12,   /* Request block hashes */
    FTC_MSG_GETHEADERS  = 13,   /* Request headers */
    FTC_MSG_HEADERS     = 14,   /* Block headers */
    FTC_MSG_MEMPOOL     = 15,   /* Request mempool */
    FTC_MSG_REJECT      = 16,   /* Rejection message */
} ftc_msg_type_t;

/*==============================================================================
 * INVENTORY TYPES
 *============================================================================*/

typedef enum {
    FTC_INV_ERROR   = 0,
    FTC_INV_TX      = 1,
    FTC_INV_BLOCK   = 2,
} ftc_inv_type_t;

typedef struct {
    uint32_t        type;
    ftc_hash256_t   hash;
} ftc_inv_t;

/*==============================================================================
 * MESSAGE HEADER (24 bytes)
 *============================================================================*/

#pragma pack(push, 1)
typedef struct {
    uint32_t    magic;          /* Network magic */
    char        command[12];    /* Command name */
    uint32_t    length;         /* Payload length */
    uint32_t    checksum;       /* First 4 bytes of Keccak(payload) */
} ftc_msg_header_t;
#pragma pack(pop)

/*==============================================================================
 * NET ADDRESS
 *============================================================================*/

typedef struct {
    uint64_t    services;       /* Service flags */
    uint8_t     ip[16];         /* IPv6 or IPv4-mapped */
    uint16_t    port;           /* Port (big-endian) */
} ftc_net_addr_t;

/*==============================================================================
 * VERSION MESSAGE
 *============================================================================*/

typedef struct {
    uint32_t        version;        /* Protocol version */
    uint64_t        services;       /* Services offered */
    int64_t         timestamp;      /* Current time */
    ftc_net_addr_t  addr_recv;      /* Receiver address */
    ftc_net_addr_t  addr_from;      /* Sender address */
    uint64_t        nonce;          /* Random nonce */
    char            user_agent[64]; /* Client identifier */
    uint32_t        start_height;   /* Best block height */
    uint8_t         relay;          /* Relay transactions? */
} ftc_version_msg_t;

/*==============================================================================
 * MESSAGE SERIALIZATION
 *============================================================================*/

/**
 * Calculate message checksum
 */
uint32_t ftc_msg_checksum(const uint8_t* payload, size_t len);

/**
 * Serialize message header
 */
void ftc_msg_header_serialize(const ftc_msg_header_t* header, uint8_t out[24]);

/**
 * Deserialize message header
 */
bool ftc_msg_header_deserialize(const uint8_t data[24], ftc_msg_header_t* header);

/**
 * Build complete message with header
 * Returns total size, or 0 on error
 */
size_t ftc_msg_build(
    ftc_msg_type_t type,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out,
    size_t out_len
);

/*==============================================================================
 * SPECIFIC MESSAGE BUILDERS
 *============================================================================*/

/**
 * Build VERSION message
 */
size_t ftc_msg_version_build(
    const ftc_version_msg_t* version,
    uint8_t* out,
    size_t out_len
);

/**
 * Build VERACK message (empty payload)
 */
size_t ftc_msg_verack_build(uint8_t* out, size_t out_len);

/**
 * Build PING/PONG message
 */
size_t ftc_msg_ping_build(uint64_t nonce, uint8_t* out, size_t out_len);
size_t ftc_msg_pong_build(uint64_t nonce, uint8_t* out, size_t out_len);

/**
 * Build GETADDR message
 */
size_t ftc_msg_getaddr_build(uint8_t* out, size_t out_len);

/**
 * Build ADDR message
 */
size_t ftc_msg_addr_build(
    const ftc_net_addr_t* addrs,
    size_t count,
    uint8_t* out,
    size_t out_len
);

/**
 * Build INV message
 */
size_t ftc_msg_inv_build(
    const ftc_inv_t* inv,
    size_t count,
    uint8_t* out,
    size_t out_len
);

/**
 * Build GETDATA message
 */
size_t ftc_msg_getdata_build(
    const ftc_inv_t* inv,
    size_t count,
    uint8_t* out,
    size_t out_len
);

/**
 * Build BLOCK message
 */
size_t ftc_msg_block_build(
    const ftc_block_t* block,
    uint8_t* out,
    size_t out_len
);

/**
 * Build TX message
 */
size_t ftc_msg_tx_build(
    const ftc_tx_t* tx,
    uint8_t* out,
    size_t out_len
);

/**
 * Build GETHEADERS message
 */
size_t ftc_msg_getheaders_build(
    const ftc_hash256_t* locator,
    size_t locator_count,
    const ftc_hash256_t stop_hash,
    uint8_t* out,
    size_t out_len
);

/**
 * Build HEADERS message
 */
size_t ftc_msg_headers_build(
    const ftc_block_header_t* headers,
    size_t count,
    uint8_t* out,
    size_t out_len
);

/*==============================================================================
 * MESSAGE TYPE HELPERS
 *============================================================================*/

/**
 * Get command string for message type
 */
const char* ftc_msg_type_to_string(ftc_msg_type_t type);

/**
 * Get message type from command string
 */
ftc_msg_type_t ftc_msg_string_to_type(const char* command);

#ifdef __cplusplus
}
#endif

#endif /* FTC_PROTOCOL_H */
