/**
 * FTC P2P Network Module
 *
 * Decentralized peer-to-peer network for block and transaction propagation.
 * Implements Bitcoin-like protocol for peer discovery and synchronization.
 */

#ifndef FTC_P2P_H
#define FTC_P2P_H

#include "../../include/ftc.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ftc_socket_t;
#define FTC_INVALID_SOCKET INVALID_SOCKET
#define FTC_SOCKET_ERROR SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
typedef int ftc_socket_t;
#define FTC_INVALID_SOCKET -1
#define FTC_SOCKET_ERROR -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * P2P CONSTANTS
 *============================================================================*/

#define FTC_P2P_PORT                17317       /* Default P2P port */
#define FTC_P2P_MAX_PEERS           125         /* Maximum peer connections */
#define FTC_P2P_MAX_OUTBOUND        8           /* Maximum outbound connections */
#define FTC_P2P_MAX_INBOUND         117         /* Maximum inbound connections */
#define FTC_P2P_HANDSHAKE_TIMEOUT   5           /* Seconds to complete handshake */
#define FTC_P2P_PING_INTERVAL       120         /* Ping every 2 minutes */
#define FTC_P2P_TIMEOUT             600         /* Disconnect after 10 min silence */
#define FTC_P2P_MAX_MESSAGE_SIZE    (4*1024*1024) /* 4 MB max message */
#define FTC_P2P_MAX_INV_SIZE        50000       /* Max items in inv message */
#define FTC_P2P_MAX_GETDATA_SIZE    50000       /* Max items in getdata */
#define FTC_P2P_MAX_ADDR_SIZE       1000        /* Max addresses in addr message */

/* Protocol version */
#define FTC_P2P_PROTOCOL_VERSION    70016
#define FTC_P2P_MIN_PROTOCOL        70001       /* Minimum supported version */

/*==============================================================================
 * MESSAGE TYPES
 *============================================================================*/

typedef enum {
    /* Handshake */
    FTC_MSG_VERSION     = 1,    /* Protocol version and capabilities */
    FTC_MSG_VERACK      = 2,    /* Version acknowledgement */

    /* Peer discovery */
    FTC_MSG_GETADDR     = 3,    /* Request peer addresses */
    FTC_MSG_ADDR        = 4,    /* Peer address list */

    /* Inventory */
    FTC_MSG_INV         = 5,    /* Inventory announcement */
    FTC_MSG_GETDATA     = 6,    /* Request data by hash */
    FTC_MSG_NOTFOUND    = 7,    /* Data not found */

    /* Blocks */
    FTC_MSG_GETBLOCKS   = 8,    /* Request block hashes */
    FTC_MSG_GETHEADERS  = 9,    /* Request block headers */
    FTC_MSG_HEADERS     = 10,   /* Block headers */
    FTC_MSG_BLOCK       = 11,   /* Full block */

    /* Transactions */
    FTC_MSG_TX          = 12,   /* Transaction */
    FTC_MSG_MEMPOOL     = 13,   /* Request mempool contents */

    /* Control */
    FTC_MSG_PING        = 14,   /* Ping */
    FTC_MSG_PONG        = 15,   /* Pong */
    FTC_MSG_REJECT      = 16,   /* Reject message */

    /* Sync */
    FTC_MSG_SENDHEADERS = 17,   /* Request headers announcements */
    FTC_MSG_SENDCMPCT   = 18,   /* Request compact blocks */

} ftc_msg_type_t;

/*==============================================================================
 * INVENTORY TYPES
 *============================================================================*/

typedef enum {
    FTC_INV_ERROR       = 0,
    FTC_INV_TX          = 1,    /* Transaction */
    FTC_INV_BLOCK       = 2,    /* Block */
    FTC_INV_FILTERED_BLOCK = 3, /* Filtered block (BIP37) */
    FTC_INV_CMPCT_BLOCK = 4,    /* Compact block */
} ftc_inv_type_t;

/*==============================================================================
 * PEER STATE
 *============================================================================*/

typedef enum {
    FTC_PEER_DISCONNECTED   = 0,
    FTC_PEER_CONNECTING     = 1,
    FTC_PEER_CONNECTED      = 2,
    FTC_PEER_VERSION_SENT   = 3,
    FTC_PEER_ESTABLISHED    = 4,    /* Handshake complete */
} ftc_peer_state_t;

/*==============================================================================
 * SERVICE FLAGS
 *============================================================================*/

typedef enum {
    FTC_NODE_NONE           = 0,
    FTC_NODE_NETWORK        = (1 << 0),  /* Full node, can serve blocks */
    FTC_NODE_GETUTXO        = (1 << 1),  /* Can serve UTXO queries */
    FTC_NODE_BLOOM          = (1 << 2),  /* Supports bloom filters */
    FTC_NODE_WITNESS        = (1 << 3),  /* Supports SegWit (future) */
    FTC_NODE_NETWORK_LIMITED = (1 << 10), /* Pruned node */
} ftc_services_t;

/*==============================================================================
 * NETWORK ADDRESS
 *============================================================================*/

typedef struct {
    uint64_t        services;           /* Service flags */
    uint8_t         ip[16];             /* IPv6 or IPv4-mapped address */
    uint16_t        port;               /* Port number */
    uint32_t        timestamp;          /* Last seen time */
    uint8_t         fail_count;         /* Connection failure count */
    uint8_t         reserved[3];        /* Padding for alignment */
} ftc_netaddr_t;

/*==============================================================================
 * MESSAGE HEADER (24 bytes)
 *============================================================================*/

#pragma pack(push, 1)
typedef struct {
    uint32_t        magic;              /* Network magic bytes */
    uint8_t         command[12];        /* Command name (null-padded) */
    uint32_t        length;             /* Payload length */
    uint32_t        checksum;           /* First 4 bytes of double SHA256 */
} ftc_msg_header_t;
#pragma pack(pop)

/*==============================================================================
 * INVENTORY VECTOR
 *============================================================================*/

typedef struct {
    uint32_t        type;               /* FTC_INV_* type */
    ftc_hash256_t   hash;               /* Object hash */
} ftc_inv_t;

/*==============================================================================
 * PEER CONNECTION
 *============================================================================*/

typedef struct ftc_peer {
    /* Socket */
    ftc_socket_t    socket;
    ftc_netaddr_t   addr;
    bool            inbound;            /* true if peer connected to us */

    /* State */
    ftc_peer_state_t state;
    time_t          connect_time;
    time_t          last_recv;
    time_t          last_send;
    time_t          last_ping;
    uint64_t        ping_nonce;
    int64_t         ping_time;          /* Round trip time in ms */

    /* Protocol info */
    int32_t         version;            /* Peer protocol version */
    uint64_t        services;           /* Peer services */
    int64_t         time_offset;        /* Peer time offset */
    char            user_agent[256];    /* Peer user agent */
    uint32_t        start_height;       /* Peer best height at connect */
    bool            relay;              /* Peer wants tx relay */

    /* Sync state */
    uint32_t        best_height;        /* Peer's current best height */
    ftc_hash256_t   best_hash;          /* Peer's best block hash */
    bool            syncing;            /* Currently syncing from this peer */
    uint32_t        blocks_in_flight;   /* Blocks requested but not received */

    /* Receive buffer */
    uint8_t*        recv_buffer;
    size_t          recv_size;
    size_t          recv_capacity;

    /* Send queue */
    uint8_t*        send_buffer;
    size_t          send_size;
    size_t          send_offset;
    size_t          send_capacity;

    /* Statistics */
    uint64_t        bytes_recv;
    uint64_t        bytes_sent;
    uint32_t        msgs_recv;
    uint32_t        msgs_sent;
    uint32_t        ban_score;          /* Misbehavior score */

    /* Peer ID */
    uint32_t        id;

} ftc_peer_t;

/*==============================================================================
 * SEED NODES
 *============================================================================*/

typedef struct {
    const char*     host;
    uint16_t        port;
} ftc_seed_t;

/* Hardcoded seed nodes - anyone can connect without DNS */
static const ftc_seed_t FTC_SEED_NODES[] = {
    /* DNS seeds (preferred - allows IP changes without binary update) */
    { "seed1.adcoin-web.com", 17317 },  /* Seoul */
    { "seed2.adcoin-web.com", 17317 },  /* Frankfurt */
    { "seed3.adcoin-web.com", 17317 },  /* Virginia */

    /* Direct IPs (fallback) */
    { "15.164.228.225",  17317 },  /* Seoul */
    { "18.194.233.15",   17317 },  /* Frankfurt */
    { "107.21.36.212",   17317 },  /* Virginia */

    { NULL, 0 }  /* Terminator */
};

/*==============================================================================
 * P2P NETWORK MANAGER
 *============================================================================*/

/* Forward declaration */
struct ftc_node;

typedef struct ftc_p2p {
    /* Configuration */
    uint16_t        port;               /* Listen port */
    uint32_t        magic;              /* Network magic */
    uint64_t        local_services;     /* Our service flags */
    bool            listen;             /* Accept incoming connections */

    /* Sockets */
    ftc_socket_t    listen_socket;      /* Listening socket */

    /* Peers */
    ftc_peer_t*     peers[FTC_P2P_MAX_PEERS];
    int             peer_count;
    int             outbound_count;
    int             inbound_count;
    uint32_t        next_peer_id;

    /* Peer database (known addresses) */
    ftc_netaddr_t*  known_addrs;
    int             known_addr_count;
    int             known_addr_capacity;

    /* State */
    bool            running;
    time_t          start_time;
    time_t          last_addr_broadcast;

    /* Node reference */
    struct ftc_node* node;

    /* Statistics */
    uint64_t        total_bytes_recv;
    uint64_t        total_bytes_sent;
    uint32_t        total_peers_connected;

    /* Sync state */
    ftc_peer_t*     sync_peer;          /* Peer we're syncing from */
    bool            initial_sync;       /* In initial block download */

    /* Orphan block cache (blocks whose parent we don't have yet) */
    #define FTC_MAX_ORPHAN_BLOCKS 100
    ftc_block_t*    orphan_blocks[100];
    int             orphan_count;

} ftc_p2p_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create P2P network manager
 */
ftc_p2p_t* ftc_p2p_new(struct ftc_node* node, uint16_t port, bool listen);

/**
 * Free P2P manager
 */
void ftc_p2p_free(ftc_p2p_t* p2p);

/**
 * Start P2P network
 */
bool ftc_p2p_start(ftc_p2p_t* p2p);

/**
 * Stop P2P network
 */
void ftc_p2p_stop(ftc_p2p_t* p2p);

/**
 * Process network events (non-blocking)
 */
void ftc_p2p_poll(ftc_p2p_t* p2p);

/**
 * Connect to a peer by address
 */
ftc_peer_t* ftc_p2p_connect(ftc_p2p_t* p2p, const char* host, uint16_t port);

/**
 * Disconnect peer
 */
void ftc_p2p_disconnect(ftc_p2p_t* p2p, ftc_peer_t* peer, const char* reason);

/**
 * Get connected peer count
 */
int ftc_p2p_peer_count(ftc_p2p_t* p2p);

/**
 * Broadcast block to all peers
 */
void ftc_p2p_broadcast_block(ftc_p2p_t* p2p, const ftc_block_t* block);

/**
 * Broadcast transaction to all peers
 */
void ftc_p2p_broadcast_tx(ftc_p2p_t* p2p, const ftc_tx_t* tx);

/**
 * Request block from peer
 */
bool ftc_p2p_request_block(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_hash256_t hash);

/**
 * Request blocks for initial sync
 */
bool ftc_p2p_sync_blocks(ftc_p2p_t* p2p);

/**
 * Add known address
 */
void ftc_p2p_add_address(ftc_p2p_t* p2p, const ftc_netaddr_t* addr);

/**
 * Save peers to file
 */
bool ftc_p2p_save_peers(ftc_p2p_t* p2p, const char* path);

/**
 * Load peers from file
 */
bool ftc_p2p_load_peers(ftc_p2p_t* p2p, const char* path);

/*==============================================================================
 * MESSAGE BUILDING
 *============================================================================*/

/**
 * Send version message
 */
bool ftc_p2p_send_version(ftc_p2p_t* p2p, ftc_peer_t* peer);

/**
 * Send verack message
 */
bool ftc_p2p_send_verack(ftc_p2p_t* p2p, ftc_peer_t* peer);

/**
 * Send ping message
 */
bool ftc_p2p_send_ping(ftc_p2p_t* p2p, ftc_peer_t* peer);

/**
 * Send pong message
 */
bool ftc_p2p_send_pong(ftc_p2p_t* p2p, ftc_peer_t* peer, uint64_t nonce);

/**
 * Send getaddr message
 */
bool ftc_p2p_send_getaddr(ftc_p2p_t* p2p, ftc_peer_t* peer);

/**
 * Send addr message
 */
bool ftc_p2p_send_addr(ftc_p2p_t* p2p, ftc_peer_t* peer,
                       const ftc_netaddr_t* addrs, int count);

/**
 * Send inv message
 */
bool ftc_p2p_send_inv(ftc_p2p_t* p2p, ftc_peer_t* peer,
                      const ftc_inv_t* inv, int count);

/**
 * Send getdata message
 */
bool ftc_p2p_send_getdata(ftc_p2p_t* p2p, ftc_peer_t* peer,
                          const ftc_inv_t* inv, int count);

/**
 * Send getblocks message
 */
bool ftc_p2p_send_getblocks(ftc_p2p_t* p2p, ftc_peer_t* peer,
                            const ftc_hash256_t* locator, int count,
                            const ftc_hash256_t stop_hash);

/**
 * Send block message
 */
bool ftc_p2p_send_block(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_t* block);

/**
 * Send tx message
 */
bool ftc_p2p_send_tx(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_tx_t* tx);

#ifdef __cplusplus
}
#endif

#endif /* FTC_P2P_H */
