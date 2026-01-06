/**
 * FTC P2P Network Layer
 *
 * Peer connection and message handling
 */

#ifndef FTC_P2P_H
#define FTC_P2P_H

#include "protocol.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ftc_socket_t;
#define FTC_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
typedef int ftc_socket_t;
#define FTC_INVALID_SOCKET -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define FTC_P2P_PORT            17317
#define FTC_MAX_PEERS           125
#define FTC_MAX_OUTBOUND        8
#define FTC_MAX_INBOUND         117
#define FTC_CONNECT_TIMEOUT     5000    /* ms */
#define FTC_HANDSHAKE_TIMEOUT   10000   /* ms */
#define FTC_PING_INTERVAL       120000  /* 2 minutes */
#define FTC_PEER_TIMEOUT        600000  /* 10 minutes */

/*==============================================================================
 * PEER STATE
 *============================================================================*/

typedef enum {
    FTC_PEER_DISCONNECTED = 0,
    FTC_PEER_CONNECTING,
    FTC_PEER_CONNECTED,
    FTC_PEER_VERSION_SENT,
    FTC_PEER_HANDSHAKED,
    FTC_PEER_SYNCING,
    FTC_PEER_ACTIVE,
} ftc_peer_state_t;

typedef enum {
    FTC_PEER_INBOUND = 0,
    FTC_PEER_OUTBOUND,
} ftc_peer_direction_t;

/*==============================================================================
 * PEER STRUCTURE
 *============================================================================*/

struct ftc_peer {
    ftc_socket_t        socket;
    ftc_peer_state_t    state;
    ftc_peer_direction_t direction;

    /* Address info */
    ftc_net_addr_t      addr;
    char                ip_str[64];

    /* Handshake info */
    uint32_t            version;
    uint64_t            services;
    uint32_t            start_height;
    char                user_agent[64];
    uint64_t            nonce;

    /* Stats */
    int64_t             connect_time;
    int64_t             last_recv;
    int64_t             last_send;
    int64_t             last_ping;
    uint64_t            ping_nonce;
    int64_t             ping_time;      /* RTT in ms */
    uint64_t            bytes_sent;
    uint64_t            bytes_recv;

    /* Receive buffer */
    uint8_t             recv_buf[FTC_MAX_MESSAGE_SIZE + 24];
    size_t              recv_len;

    /* Flags */
    bool                relay;
    bool                disconnect_requested;

    /* Sync state */
    int32_t             sync_height;
    bool                headers_synced;

};

/*==============================================================================
 * P2P MANAGER
 *============================================================================*/

/* Forward declarations */
struct ftc_p2p_callbacks;

typedef struct {
    /* Server socket */
    ftc_socket_t        listen_socket;
    uint16_t            listen_port;
    bool                listening;

    /* Peers */
    ftc_peer_t*         peers[FTC_MAX_PEERS];
    int                 peer_count;
    int                 outbound_count;
    int                 inbound_count;

    /* Our info */
    uint64_t            local_nonce;
    uint64_t            local_services;
    uint32_t            best_height;

    /* Seed nodes */
    const char**        seed_nodes;
    int                 seed_count;

    /* Callbacks */
    struct ftc_p2p_callbacks* callbacks;
    void*               user_data;

    /* State */
    bool                running;
    int64_t             last_peer_check;

} ftc_p2p_t;

/*==============================================================================
 * CALLBACKS
 *============================================================================*/

typedef struct ftc_p2p_callbacks {
    /* Called when a peer connects/disconnects */
    void (*on_peer_connected)(ftc_p2p_t* p2p, ftc_peer_t* peer);
    void (*on_peer_disconnected)(ftc_p2p_t* p2p, ftc_peer_t* peer);

    /* Called for each received message */
    void (*on_version)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_version_msg_t* msg);
    void (*on_inv)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_inv_t* inv, size_t count);
    void (*on_block)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_t* block);
    void (*on_tx)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_tx_t* tx);
    void (*on_headers)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_header_t* headers, size_t count);
    void (*on_addr)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_net_addr_t* addrs, size_t count);
    void (*on_getdata)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_inv_t* inv, size_t count);
    void (*on_getheaders)(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_hash256_t* locator, size_t count, const ftc_hash256_t stop_hash);

} ftc_p2p_callbacks_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Initialize P2P networking
 */
ftc_p2p_t* ftc_p2p_new(void);

/**
 * Free P2P resources
 */
void ftc_p2p_free(ftc_p2p_t* p2p);

/**
 * Set callbacks
 */
void ftc_p2p_set_callbacks(ftc_p2p_t* p2p, ftc_p2p_callbacks_t* callbacks, void* user_data);

/**
 * Add seed nodes
 */
void ftc_p2p_add_seed(ftc_p2p_t* p2p, const char* host);

/**
 * Start listening for connections
 */
bool ftc_p2p_start(ftc_p2p_t* p2p, uint16_t port);

/**
 * Stop P2P networking
 */
void ftc_p2p_stop(ftc_p2p_t* p2p);

/**
 * Connect to a peer
 */
ftc_peer_t* ftc_p2p_connect(ftc_p2p_t* p2p, const char* host, uint16_t port);

/**
 * Disconnect a peer
 */
void ftc_p2p_disconnect(ftc_p2p_t* p2p, ftc_peer_t* peer);

/**
 * Process network events (call periodically)
 */
void ftc_p2p_poll(ftc_p2p_t* p2p, int timeout_ms);

/**
 * Update best height
 */
void ftc_p2p_set_height(ftc_p2p_t* p2p, uint32_t height);

/*==============================================================================
 * MESSAGE SENDING
 *============================================================================*/

/**
 * Send raw message to peer
 */
bool ftc_peer_send(ftc_peer_t* peer, const uint8_t* data, size_t len);

/**
 * Send specific messages
 */
bool ftc_peer_send_version(ftc_p2p_t* p2p, ftc_peer_t* peer);
bool ftc_peer_send_verack(ftc_peer_t* peer);
bool ftc_peer_send_ping(ftc_peer_t* peer);
bool ftc_peer_send_pong(ftc_peer_t* peer, uint64_t nonce);
bool ftc_peer_send_getaddr(ftc_peer_t* peer);
bool ftc_peer_send_addr(ftc_peer_t* peer, const ftc_net_addr_t* addrs, size_t count);
bool ftc_peer_send_inv(ftc_peer_t* peer, const ftc_inv_t* inv, size_t count);
bool ftc_peer_send_getdata(ftc_peer_t* peer, const ftc_inv_t* inv, size_t count);
bool ftc_peer_send_block(ftc_peer_t* peer, const ftc_block_t* block);
bool ftc_peer_send_tx(ftc_peer_t* peer, const ftc_tx_t* tx);
bool ftc_peer_send_getheaders(ftc_peer_t* peer, const ftc_hash256_t* locator, size_t count, const ftc_hash256_t stop_hash);
bool ftc_peer_send_headers(ftc_peer_t* peer, const ftc_block_header_t* headers, size_t count);

/*==============================================================================
 * BROADCAST
 *============================================================================*/

/**
 * Broadcast block to all connected peers
 */
void ftc_p2p_broadcast_block(ftc_p2p_t* p2p, const ftc_block_t* block);

/**
 * Broadcast transaction to all connected peers
 */
void ftc_p2p_broadcast_tx(ftc_p2p_t* p2p, const ftc_tx_t* tx);

/**
 * Broadcast inventory to all connected peers
 */
void ftc_p2p_broadcast_inv(ftc_p2p_t* p2p, const ftc_inv_t* inv, size_t count);

/*==============================================================================
 * UTILITIES
 *============================================================================*/

/**
 * Get current timestamp in milliseconds
 */
int64_t ftc_time_ms(void);

/**
 * Parse IPv4/IPv6 address to ftc_net_addr_t
 */
bool ftc_parse_address(const char* str, uint16_t port, ftc_net_addr_t* addr);

/**
 * Format address to string
 */
void ftc_format_address(const ftc_net_addr_t* addr, char* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FTC_P2P_H */
