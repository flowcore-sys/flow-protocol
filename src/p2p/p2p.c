/**
 * FTC P2P Network Implementation
 */

#include "p2p.h"
#include "../core/block.h"
#include "../core/tx.h"
#include "../crypto/keccak256.h"
#include "../../node/full_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define MSG_NOSIGNAL 0
static bool wsa_initialized = false;
#else
#include <netdb.h>
#include <signal.h>
#endif

/* Cross-platform unused attribute */
#ifdef _MSC_VER
#define MAYBE_UNUSED
#else
#define MAYBE_UNUSED __attribute__((unused))
#endif

/*==============================================================================
 * FORWARD DECLARATIONS
 *============================================================================*/

static void mark_address_failed(ftc_p2p_t* p2p, const uint8_t* ip, uint16_t port);
static const char* format_addr(const ftc_netaddr_t* addr);

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

static void log_p2p(const char* fmt, ...) {
    (void)fmt;  /* Silent mode */
}

MAYBE_UNUSED
static uint32_t hash_to_index(const uint8_t* data, size_t len) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

/* Calculate checksum (first 4 bytes of double Keccak256) */
static uint32_t calc_checksum(const uint8_t* data, size_t len) {
    ftc_hash256_t hash1, hash2;
    ftc_keccak256(data, len, hash1);
    ftc_keccak256(hash1, 32, hash2);
    return *(uint32_t*)hash2;
}

/* Set socket to non-blocking */
static bool set_nonblocking(ftc_socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

/* Get error string */
static const char* sock_error(void) {
#ifdef _WIN32
    static char buf[256];
    int err = WSAGetLastError();
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, sizeof(buf), NULL);
    return buf;
#else
    return strerror(errno);
#endif
}

/* Convert IPv4 to IPv6-mapped format */
static void ipv4_to_ipv6(uint32_t ipv4, uint8_t* ipv6) {
    memset(ipv6, 0, 10);
    ipv6[10] = 0xff;
    ipv6[11] = 0xff;
    memcpy(ipv6 + 12, &ipv4, 4);
}

/* Format address for logging */
static const char* format_addr(const ftc_netaddr_t* addr) {
    static char buf[64];
    /* Check if IPv4-mapped */
    if (memcmp(addr->ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d:%d",
                 addr->ip[12], addr->ip[13], addr->ip[14], addr->ip[15],
                 addr->port);
    } else {
        snprintf(buf, sizeof(buf), "[ipv6]:%d", addr->port);
    }
    return buf;
}

/*==============================================================================
 * PEER MANAGEMENT
 *============================================================================*/

static ftc_peer_t* peer_new(void) {
    ftc_peer_t* peer = calloc(1, sizeof(ftc_peer_t));
    if (!peer) return NULL;

    peer->socket = FTC_INVALID_SOCKET;
    peer->state = FTC_PEER_DISCONNECTED;
    peer->recv_capacity = 64 * 1024;  /* 64KB initial buffer */
    peer->recv_buffer = malloc(peer->recv_capacity);
    peer->send_capacity = 64 * 1024;
    peer->send_buffer = malloc(peer->send_capacity);

    if (!peer->recv_buffer || !peer->send_buffer) {
        free(peer->recv_buffer);
        free(peer->send_buffer);
        free(peer);
        return NULL;
    }

    return peer;
}

static void peer_free(ftc_peer_t* peer) {
    if (!peer) return;
    if (peer->socket != FTC_INVALID_SOCKET) {
        close(peer->socket);
    }
    free(peer->recv_buffer);
    free(peer->send_buffer);
    free(peer);
}

static bool peer_add_to_list(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        if (p2p->peers[i] == NULL) {
            p2p->peers[i] = peer;
            peer->id = p2p->next_peer_id++;
            p2p->peer_count++;
            if (peer->inbound) {
                p2p->inbound_count++;
            } else {
                p2p->outbound_count++;
            }
            return true;
        }
    }
    return false;
}

static void peer_remove_from_list(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        if (p2p->peers[i] == peer) {
            p2p->peers[i] = NULL;
            p2p->peer_count--;
            if (peer->inbound) {
                p2p->inbound_count--;
            } else {
                p2p->outbound_count--;
            }
            if (p2p->sync_peer == peer) {
                p2p->sync_peer = NULL;
            }
            break;
        }
    }
}

/*==============================================================================
 * SOCKET OPERATIONS
 *============================================================================*/

static bool init_sockets(void) {
#ifdef _WIN32
    if (!wsa_initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            log_p2p("WSAStartup failed");
            return false;
        }
        wsa_initialized = true;
    }
#else
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif
    return true;
}

static ftc_socket_t create_listen_socket(uint16_t port) {
    ftc_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == FTC_INVALID_SOCKET) {
        log_p2p("Failed to create socket: %s", sock_error());
        return FTC_INVALID_SOCKET;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == FTC_SOCKET_ERROR) {
        log_p2p("Failed to bind port %d: %s", port, sock_error());
        close(sock);
        return FTC_INVALID_SOCKET;
    }

    /* Listen */
    if (listen(sock, 10) == FTC_SOCKET_ERROR) {
        log_p2p("Failed to listen: %s", sock_error());
        close(sock);
        return FTC_INVALID_SOCKET;
    }

    set_nonblocking(sock);
    return sock;
}

/*==============================================================================
 * MESSAGE SERIALIZATION
 *============================================================================*/

/* Command names */
MAYBE_UNUSED
static const char* msg_command(ftc_msg_type_t type) {
    switch (type) {
        case FTC_MSG_VERSION:     return "version";
        case FTC_MSG_VERACK:      return "verack";
        case FTC_MSG_GETADDR:     return "getaddr";
        case FTC_MSG_ADDR:        return "addr";
        case FTC_MSG_INV:         return "inv";
        case FTC_MSG_GETDATA:     return "getdata";
        case FTC_MSG_NOTFOUND:    return "notfound";
        case FTC_MSG_GETBLOCKS:   return "getblocks";
        case FTC_MSG_GETHEADERS:  return "getheaders";
        case FTC_MSG_HEADERS:     return "headers";
        case FTC_MSG_BLOCK:       return "block";
        case FTC_MSG_TX:          return "tx";
        case FTC_MSG_MEMPOOL:     return "mempool";
        case FTC_MSG_PING:        return "ping";
        case FTC_MSG_PONG:        return "pong";
        case FTC_MSG_REJECT:      return "reject";
        case FTC_MSG_SENDHEADERS: return "sendheaders";
        case FTC_MSG_SENDCMPCT:   return "sendcmpct";
        default:                  return "unknown";
    }
}

static ftc_msg_type_t msg_type_from_command(const char* cmd) {
    if (strcmp(cmd, "version") == 0)     return FTC_MSG_VERSION;
    if (strcmp(cmd, "verack") == 0)      return FTC_MSG_VERACK;
    if (strcmp(cmd, "getaddr") == 0)     return FTC_MSG_GETADDR;
    if (strcmp(cmd, "addr") == 0)        return FTC_MSG_ADDR;
    if (strcmp(cmd, "inv") == 0)         return FTC_MSG_INV;
    if (strcmp(cmd, "getdata") == 0)     return FTC_MSG_GETDATA;
    if (strcmp(cmd, "notfound") == 0)    return FTC_MSG_NOTFOUND;
    if (strcmp(cmd, "getblocks") == 0)   return FTC_MSG_GETBLOCKS;
    if (strcmp(cmd, "getheaders") == 0)  return FTC_MSG_GETHEADERS;
    if (strcmp(cmd, "headers") == 0)     return FTC_MSG_HEADERS;
    if (strcmp(cmd, "block") == 0)       return FTC_MSG_BLOCK;
    if (strcmp(cmd, "tx") == 0)          return FTC_MSG_TX;
    if (strcmp(cmd, "mempool") == 0)     return FTC_MSG_MEMPOOL;
    if (strcmp(cmd, "ping") == 0)        return FTC_MSG_PING;
    if (strcmp(cmd, "pong") == 0)        return FTC_MSG_PONG;
    if (strcmp(cmd, "reject") == 0)      return FTC_MSG_REJECT;
    if (strcmp(cmd, "sendheaders") == 0) return FTC_MSG_SENDHEADERS;
    if (strcmp(cmd, "sendcmpct") == 0)   return FTC_MSG_SENDCMPCT;
    return 0;
}

/* Prepare message header */
static void prepare_header(ftc_msg_header_t* hdr, uint32_t magic,
                           const char* command, const uint8_t* payload, size_t len) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = magic;
    size_t cmd_len = strlen(command);
    if (cmd_len > 12) cmd_len = 12;
    memcpy(hdr->command, command, cmd_len);
    hdr->length = (uint32_t)len;
    hdr->checksum = calc_checksum(payload, len);
}

/* Queue message for sending */
static bool queue_message(ftc_peer_t* peer, uint32_t magic,
                          const char* command, const uint8_t* payload, size_t len) {
    size_t total = sizeof(ftc_msg_header_t) + len;

    /* Grow buffer if needed */
    while (peer->send_size + total > peer->send_capacity) {
        size_t new_cap = peer->send_capacity * 2;
        uint8_t* new_buf = realloc(peer->send_buffer, new_cap);
        if (!new_buf) return false;
        peer->send_buffer = new_buf;
        peer->send_capacity = new_cap;
    }

    /* Add header */
    ftc_msg_header_t hdr;
    prepare_header(&hdr, magic, command, payload, len);
    memcpy(peer->send_buffer + peer->send_size, &hdr, sizeof(hdr));
    peer->send_size += sizeof(hdr);

    /* Add payload */
    if (len > 0) {
        memcpy(peer->send_buffer + peer->send_size, payload, len);
        peer->send_size += len;
    }

    return true;
}

/*==============================================================================
 * MESSAGE SENDING
 *============================================================================*/

bool ftc_p2p_send_version(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    /* Version message format:
     * int32   version
     * uint64  services
     * int64   timestamp
     * netaddr addr_recv (26 bytes)
     * netaddr addr_from (26 bytes)
     * uint64  nonce
     * varstr  user_agent
     * int32   start_height
     * bool    relay
     */
    uint8_t payload[256];
    size_t offset = 0;

    /* Version */
    int32_t version = FTC_P2P_PROTOCOL_VERSION;
    memcpy(payload + offset, &version, 4); offset += 4;

    /* Services */
    uint64_t services = p2p->local_services;
    memcpy(payload + offset, &services, 8); offset += 8;

    /* Timestamp */
    int64_t timestamp = (int64_t)time(NULL);
    memcpy(payload + offset, &timestamp, 8); offset += 8;

    /* Addr recv (simplified - 26 bytes) */
    memcpy(payload + offset, &peer->addr.services, 8); offset += 8;
    memcpy(payload + offset, peer->addr.ip, 16); offset += 16;
    uint16_t port_be = htons(peer->addr.port);
    memcpy(payload + offset, &port_be, 2); offset += 2;

    /* Addr from (simplified - 26 bytes) */
    memset(payload + offset, 0, 26); offset += 26;

    /* Nonce */
    uint64_t nonce = ((uint64_t)rand() << 32) | rand();
    memcpy(payload + offset, &nonce, 8); offset += 8;

    /* User agent (varint + string) */
    const char* ua = FTC_USER_AGENT;
    size_t ua_len = strlen(ua);
    payload[offset++] = (uint8_t)ua_len;
    memcpy(payload + offset, ua, ua_len); offset += ua_len;

    /* Start height */
    uint32_t height = p2p->node ? ((ftc_node_t*)p2p->node)->chain->block_count - 1 : 0;
    memcpy(payload + offset, &height, 4); offset += 4;

    /* Relay */
    payload[offset++] = 1;

    return queue_message(peer, p2p->magic, "version", payload, offset);
}

bool ftc_p2p_send_verack(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    return queue_message(peer, p2p->magic, "verack", NULL, 0);
}

bool ftc_p2p_send_ping(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    peer->ping_nonce = ((uint64_t)rand() << 32) | rand();
    peer->last_ping = time(NULL);
    return queue_message(peer, p2p->magic, "ping", (uint8_t*)&peer->ping_nonce, 8);
}

bool ftc_p2p_send_pong(ftc_p2p_t* p2p, ftc_peer_t* peer, uint64_t nonce) {
    return queue_message(peer, p2p->magic, "pong", (uint8_t*)&nonce, 8);
}

bool ftc_p2p_send_getaddr(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    return queue_message(peer, p2p->magic, "getaddr", NULL, 0);
}

bool ftc_p2p_send_addr(ftc_p2p_t* p2p, ftc_peer_t* peer,
                       const ftc_netaddr_t* addrs, int count) {
    if (count > FTC_P2P_MAX_ADDR_SIZE) count = FTC_P2P_MAX_ADDR_SIZE;

    size_t payload_size = 1 + count * 30;  /* varint + count * (timestamp + netaddr) */
    uint8_t* payload = malloc(payload_size);
    if (!payload) return false;

    size_t offset = 0;
    payload[offset++] = (uint8_t)count;

    for (int i = 0; i < count; i++) {
        memcpy(payload + offset, &addrs[i].timestamp, 4); offset += 4;
        memcpy(payload + offset, &addrs[i].services, 8); offset += 8;
        memcpy(payload + offset, addrs[i].ip, 16); offset += 16;
        uint16_t port_be = htons(addrs[i].port);
        memcpy(payload + offset, &port_be, 2); offset += 2;
    }

    bool ok = queue_message(peer, p2p->magic, "addr", payload, offset);
    free(payload);
    return ok;
}

bool ftc_p2p_send_inv(ftc_p2p_t* p2p, ftc_peer_t* peer,
                      const ftc_inv_t* inv, int count) {
    if (count > FTC_P2P_MAX_INV_SIZE) count = FTC_P2P_MAX_INV_SIZE;

    size_t payload_size = 3 + count * 36;  /* varint + count * (type + hash) */
    uint8_t* payload = malloc(payload_size);
    if (!payload) return false;

    size_t offset = 0;
    /* Encode count as varint */
    if (count < 253) {
        payload[offset++] = (uint8_t)count;
    } else {
        payload[offset++] = 253;
        payload[offset++] = count & 0xff;
        payload[offset++] = (count >> 8) & 0xff;
    }

    for (int i = 0; i < count; i++) {
        memcpy(payload + offset, &inv[i].type, 4); offset += 4;
        memcpy(payload + offset, inv[i].hash, 32); offset += 32;
    }

    bool ok = queue_message(peer, p2p->magic, "inv", payload, offset);
    free(payload);
    return ok;
}

bool ftc_p2p_send_getdata(ftc_p2p_t* p2p, ftc_peer_t* peer,
                          const ftc_inv_t* inv, int count) {
    if (count > FTC_P2P_MAX_GETDATA_SIZE) count = FTC_P2P_MAX_GETDATA_SIZE;

    size_t payload_size = 3 + count * 36;
    uint8_t* payload = malloc(payload_size);
    if (!payload) return false;

    size_t offset = 0;
    if (count < 253) {
        payload[offset++] = (uint8_t)count;
    } else {
        payload[offset++] = 253;
        payload[offset++] = count & 0xff;
        payload[offset++] = (count >> 8) & 0xff;
    }

    for (int i = 0; i < count; i++) {
        memcpy(payload + offset, &inv[i].type, 4); offset += 4;
        memcpy(payload + offset, inv[i].hash, 32); offset += 32;
    }

    bool ok = queue_message(peer, p2p->magic, "getdata", payload, offset);
    free(payload);
    return ok;
}

bool ftc_p2p_send_getblocks(ftc_p2p_t* p2p, ftc_peer_t* peer,
                            const ftc_hash256_t* locator, int count,
                            const ftc_hash256_t stop_hash) {
    size_t payload_size = 4 + 1 + count * 32 + 32;
    uint8_t* payload = malloc(payload_size);
    if (!payload) return false;

    size_t offset = 0;

    /* Version */
    uint32_t version = FTC_P2P_PROTOCOL_VERSION;
    memcpy(payload + offset, &version, 4); offset += 4;

    /* Locator count */
    payload[offset++] = (uint8_t)count;

    /* Locator hashes */
    for (int i = 0; i < count; i++) {
        memcpy(payload + offset, locator[i], 32); offset += 32;
    }

    /* Stop hash */
    memcpy(payload + offset, stop_hash, 32); offset += 32;

    bool ok = queue_message(peer, p2p->magic, "getblocks", payload, offset);
    free(payload);
    return ok;
}

bool ftc_p2p_send_block(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_block_t* block) {
    /* Serialize block - first get size by passing NULL */
    size_t size = ftc_block_serialize(block, NULL, 0);
    if (size == 0) return false;

    uint8_t* payload = malloc(size);
    if (!payload) return false;

    ftc_block_serialize(block, payload, size);
    bool ok = queue_message(peer, p2p->magic, "block", payload, size);
    free(payload);
    return ok;
}

bool ftc_p2p_send_tx(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_tx_t* tx) {
    /* Serialize tx - first get size by passing NULL */
    size_t size = ftc_tx_serialize(tx, NULL, 0);
    if (size == 0) return false;

    uint8_t* payload = malloc(size);
    if (!payload) return false;

    ftc_tx_serialize(tx, payload, size);
    bool ok = queue_message(peer, p2p->magic, "tx", payload, size);
    free(payload);
    return ok;
}

/*==============================================================================
 * MESSAGE HANDLING
 *============================================================================*/

static void handle_version(ftc_p2p_t* p2p, ftc_peer_t* peer,
                           const uint8_t* payload, size_t len) {
    if (len < 85) {
        log_p2p("Version message too short");
        return;
    }

    size_t offset = 0;

    /* Parse version */
    memcpy(&peer->version, payload + offset, 4); offset += 4;
    memcpy(&peer->services, payload + offset, 8); offset += 8;

    int64_t timestamp;
    memcpy(&timestamp, payload + offset, 8); offset += 8;
    peer->time_offset = timestamp - time(NULL);

    /* Skip addresses (52 bytes) */
    offset += 52;

    /* Skip nonce */
    offset += 8;

    /* User agent */
    if (offset < len) {
        uint8_t ua_len = payload[offset++];
        if (offset + ua_len <= len) {
            size_t copy_len = ua_len < 255 ? ua_len : 255;
            memcpy(peer->user_agent, payload + offset, copy_len);
            peer->user_agent[copy_len] = 0;
            offset += ua_len;
        }
    }

    /* Start height */
    if (offset + 4 <= len) {
        memcpy(&peer->start_height, payload + offset, 4);
        peer->best_height = peer->start_height;
        offset += 4;
    }

    /* Relay */
    if (offset < len) {
        peer->relay = payload[offset] != 0;
    }

    /* Check protocol version */
    if (peer->version < FTC_P2P_MIN_PROTOCOL) {
        log_p2p("Peer protocol version too old: %d", peer->version);
        ftc_p2p_disconnect(p2p, peer, "protocol too old");
        return;
    }

    /* Send verack */
    ftc_p2p_send_verack(p2p, peer);

    /* If we haven't sent version yet, send it now */
    if (peer->state < FTC_PEER_VERSION_SENT) {
        ftc_p2p_send_version(p2p, peer);
        peer->state = FTC_PEER_VERSION_SENT;
    }

    /* For outbound connections, we receive VERSION after VERACK.
     * Check if handshake is complete and we should start sync. */
    if (peer->state == FTC_PEER_ESTABLISHED) {
        ftc_node_t* node = (ftc_node_t*)p2p->node;
        if (node && peer->start_height > node->chain->block_count - 1) {
            if (!p2p->sync_peer) {
                p2p->sync_peer = peer;
                peer->syncing = true;
                log_p2p("Starting sync from %s (height %u)",
                        format_addr(&peer->addr), peer->start_height);
                ftc_p2p_sync_blocks(p2p);
            }
        }
    }
}

/* Reset fail count for address on successful connection */
static void reset_address_fail_count(ftc_p2p_t* p2p, const uint8_t* ip, uint16_t port) {
    for (int i = 0; i < p2p->known_addr_count; i++) {
        if (memcmp(p2p->known_addrs[i].ip, ip, 16) == 0 &&
            p2p->known_addrs[i].port == port) {
            p2p->known_addrs[i].fail_count = 0;
            return;
        }
    }
}

static void handle_verack(ftc_p2p_t* p2p, ftc_peer_t* peer,
                          const uint8_t* payload, size_t len) {
    (void)payload; (void)len;

    peer->state = FTC_PEER_ESTABLISHED;
    p2p->total_peers_connected++;

    /* Reset fail count - peer is reachable */
    reset_address_fail_count(p2p, peer->addr.ip, peer->addr.port);

    log_p2p("Handshake complete with %s", format_addr(&peer->addr));

    /* Request addresses */
    ftc_p2p_send_getaddr(p2p, peer);

    /* For inbound connections, we already have peer->start_height from VERSION.
     * Check if we should start sync. */
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (node && peer->start_height > 0 && peer->start_height > node->chain->block_count - 1) {
        if (!p2p->sync_peer) {
            p2p->sync_peer = peer;
            peer->syncing = true;
            ftc_p2p_sync_blocks(p2p);
        }
    }
}

static void handle_ping(ftc_p2p_t* p2p, ftc_peer_t* peer,
                        const uint8_t* payload, size_t len) {
    if (len >= 8) {
        uint64_t nonce;
        memcpy(&nonce, payload, 8);
        ftc_p2p_send_pong(p2p, peer, nonce);
    }
}

static void handle_pong(ftc_p2p_t* p2p, ftc_peer_t* peer,
                        const uint8_t* payload, size_t len) {
    (void)p2p;
    if (len >= 8) {
        uint64_t nonce;
        memcpy(&nonce, payload, 8);
        if (nonce == peer->ping_nonce) {
            peer->ping_time = (time(NULL) - peer->last_ping) * 1000;
        }
    }
}

static void handle_addr(ftc_p2p_t* p2p, ftc_peer_t* peer,
                        const uint8_t* payload, size_t len) {
    (void)peer;
    if (len < 1) return;

    size_t offset = 0;
    uint64_t count = payload[offset++];

    if (count == 253 && len >= 3) {
        count = payload[offset] | (payload[offset + 1] << 8);
        offset += 2;
    }

    if (count > FTC_P2P_MAX_ADDR_SIZE) count = FTC_P2P_MAX_ADDR_SIZE;

    log_p2p("Received %llu addresses", (unsigned long long)count);

    for (uint64_t i = 0; i < count && offset + 30 <= len; i++) {
        ftc_netaddr_t addr;
        memcpy(&addr.timestamp, payload + offset, 4); offset += 4;
        memcpy(&addr.services, payload + offset, 8); offset += 8;
        memcpy(addr.ip, payload + offset, 16); offset += 16;
        uint16_t port_be;
        memcpy(&port_be, payload + offset, 2); offset += 2;
        addr.port = ntohs(port_be);

        ftc_p2p_add_address(p2p, &addr);
    }
}

static void handle_inv(ftc_p2p_t* p2p, ftc_peer_t* peer,
                       const uint8_t* payload, size_t len) {
    if (len < 1) return;

    size_t offset = 0;
    uint64_t count = payload[offset++];

    if (count == 253 && len >= 3) {
        count = payload[offset] | (payload[offset + 1] << 8);
        offset += 2;
    }

    /* Collect items we need */
    ftc_inv_t* needed = malloc(count * sizeof(ftc_inv_t));
    if (!needed) return;
    int needed_count = 0;

    ftc_node_t* node = (ftc_node_t*)p2p->node;

    for (uint64_t i = 0; i < count && offset + 36 <= len; i++) {
        ftc_inv_t inv;
        memcpy(&inv.type, payload + offset, 4); offset += 4;
        memcpy(inv.hash, payload + offset, 32); offset += 32;

        /* Check if we have this item */
        bool have = false;
        if (inv.type == FTC_INV_BLOCK && node) {
            have = ftc_chain_get_block(node->chain, inv.hash) != NULL;
        } else if (inv.type == FTC_INV_TX && node) {
            have = ftc_mempool_get(node->mempool, inv.hash) != NULL;
        }

        if (!have) {
            needed[needed_count++] = inv;
        }
    }

    /* Request needed items */
    if (needed_count > 0) {
        ftc_p2p_send_getdata(p2p, peer, needed, needed_count);

        /* Track blocks in flight for sync continuation */
        if (peer->syncing) {
            int blocks_needed = 0;
            for (int i = 0; i < needed_count; i++) {
                if (needed[i].type == FTC_INV_BLOCK) blocks_needed++;
            }
            peer->blocks_in_flight += blocks_needed;
        }
    }

    free(needed);
}

/* Check if block's prev_hash matches our tip */
static bool block_connects_to_tip(ftc_node_t* node, const ftc_block_t* block) {
    if (node->chain->block_count == 0) return true;

    ftc_hash256_t tip_hash;
    ftc_block_hash(node->chain->blocks[node->chain->block_count - 1], tip_hash);
    return memcmp(block->header.prev_hash, tip_hash, 32) == 0;
}

/* Store block as orphan */
static bool store_orphan(ftc_p2p_t* p2p, ftc_block_t* block) {
    if (p2p->orphan_count >= FTC_MAX_ORPHAN_BLOCKS) {
        /* Cache full - remove oldest */
        ftc_block_free(p2p->orphan_blocks[0]);
        memmove(p2p->orphan_blocks, p2p->orphan_blocks + 1,
                (FTC_MAX_ORPHAN_BLOCKS - 1) * sizeof(ftc_block_t*));
        p2p->orphan_count--;
    }
    p2p->orphan_blocks[p2p->orphan_count++] = block;
    return true;
}

/* Try to add orphan blocks that now connect */
static void process_orphans(ftc_p2p_t* p2p) {
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node) return;

    bool added_any;
    do {
        added_any = false;
        for (int i = 0; i < p2p->orphan_count; i++) {
            ftc_block_t* orphan = p2p->orphan_blocks[i];
            if (block_connects_to_tip(node, orphan)) {
                if (ftc_chain_add_block(node, orphan)) {
                    /* Remove from orphan list */
                    ftc_block_free(orphan);
                    memmove(p2p->orphan_blocks + i, p2p->orphan_blocks + i + 1,
                            (p2p->orphan_count - i - 1) * sizeof(ftc_block_t*));
                    p2p->orphan_count--;
                    i--;  /* Recheck this position */
                    added_any = true;
                }
            }
        }
    } while (added_any);  /* Keep trying until no more orphans connect */
}

static void handle_block(ftc_p2p_t* p2p, ftc_peer_t* peer,
                         const uint8_t* payload, size_t len) {
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node) return;

    /* Deserialize block */
    ftc_block_t* block = ftc_block_deserialize(payload, len);
    if (!block) {
        peer->ban_score += 10;
        return;
    }

    /* Check if block connects to our tip */
    if (block_connects_to_tip(node, block)) {
        /* Block connects - try to add */
        if (ftc_chain_add_block(node, block)) {
            /* Broadcast to other peers */
            ftc_p2p_broadcast_block(p2p, block);

            /* Check if orphans now connect */
            process_orphans(p2p);

            /* Continue sync if needed */
            if (peer->syncing) {
                peer->blocks_in_flight--;
                if (peer->blocks_in_flight == 0) {
                    ftc_p2p_sync_blocks(p2p);
                }
            }
        }
        ftc_block_free(block);  /* Always free - add_block clones */
    } else {
        /* Block doesn't connect - check if we already have it */
        ftc_hash256_t block_hash;
        ftc_block_hash(block, block_hash);
        if (ftc_chain_get_block(node->chain, block_hash) != NULL) {
            /* Already have this block */
            ftc_block_free(block);
            return;
        }

        /* Store as orphan for later */
        store_orphan(p2p, block);  /* Ownership transferred to orphan cache */

        /* Track for sync continuation */
        if (peer->syncing) {
            peer->blocks_in_flight--;
            if (peer->blocks_in_flight == 0) {
                ftc_p2p_sync_blocks(p2p);
            }
        }
    }
}

static void handle_tx(ftc_p2p_t* p2p, ftc_peer_t* peer,
                      const uint8_t* payload, size_t len) {
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node) return;

    /* Deserialize transaction */
    size_t consumed = 0;
    ftc_tx_t* tx = ftc_tx_deserialize(payload, len, &consumed);
    if (!tx) {
        log_p2p("Failed to deserialize tx from %s", format_addr(&peer->addr));
        peer->ban_score += 10;
        return;
    }

    /* Validate and add to mempool */
    if (ftc_node_validate_tx(node, tx)) {
        uint32_t height = node->chain->block_count > 0 ? node->chain->block_count - 1 : 0;
        if (ftc_mempool_add(node->mempool, tx, node->utxo_set, height) == FTC_OK) {
            /* Broadcast to other peers */
            ftc_p2p_broadcast_tx(p2p, tx);
        }
    } else {
        log_p2p("Invalid tx from %s", format_addr(&peer->addr));
        peer->ban_score += 10;
        ftc_tx_free(tx);
    }
}

static void handle_getblocks(ftc_p2p_t* p2p, ftc_peer_t* peer,
                             const uint8_t* payload, size_t len) {
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node || len < 37) return;

    size_t offset = 4;  /* Skip version */

    /* Get locator count */
    uint8_t locator_count = payload[offset++];

    /* Find common block */
    int start_height = 0;
    for (int i = 0; i < locator_count && offset + 32 <= len; i++) {
        ftc_block_t* block = ftc_chain_get_block(node->chain, payload + offset);
        offset += 32;
        if (block) {
            /* Find height of this block */
            for (int h = 0; h < node->chain->block_count; h++) {
                if (node->chain->blocks[h] == block) {
                    start_height = h + 1;
                    break;
                }
            }
            break;
        }
    }

    /* Send inv for blocks after start_height */
    int count = node->chain->block_count - start_height;
    if (count > 500) count = 500;  /* Max 500 at a time */

    if (count > 0) {
        ftc_inv_t* inv = malloc(count * sizeof(ftc_inv_t));
        if (inv) {
            for (int i = 0; i < count; i++) {
                inv[i].type = FTC_INV_BLOCK;
                ftc_block_hash(node->chain->blocks[start_height + i], inv[i].hash);
            }
            ftc_p2p_send_inv(p2p, peer, inv, count);
            free(inv);
        }
    }
}

static void handle_getdata(ftc_p2p_t* p2p, ftc_peer_t* peer,
                           const uint8_t* payload, size_t len) {
    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node || len < 1) return;

    size_t offset = 0;
    uint64_t count = payload[offset++];

    if (count == 253 && len >= 3) {
        count = payload[offset] | (payload[offset + 1] << 8);
        offset += 2;
    }

    for (uint64_t i = 0; i < count && offset + 36 <= len; i++) {
        uint32_t type;
        ftc_hash256_t hash;
        memcpy(&type, payload + offset, 4); offset += 4;
        memcpy(hash, payload + offset, 32); offset += 32;

        if (type == FTC_INV_BLOCK) {
            ftc_block_t* block = ftc_chain_get_block(node->chain, hash);
            if (block) {
                ftc_p2p_send_block(p2p, peer, block);
            }
        } else if (type == FTC_INV_TX) {
            const ftc_tx_t* tx = ftc_mempool_get(node->mempool, hash);
            if (tx) {
                ftc_p2p_send_tx(p2p, peer, tx);
            }
        }
    }
}

static void process_message(ftc_p2p_t* p2p, ftc_peer_t* peer,
                            const ftc_msg_header_t* hdr,
                            const uint8_t* payload) {
    char cmd[13] = {0};
    memcpy(cmd, hdr->command, 12);

    ftc_msg_type_t type = msg_type_from_command(cmd);

    peer->msgs_recv++;
    peer->last_recv = time(NULL);

    switch (type) {
        case FTC_MSG_VERSION:
            handle_version(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_VERACK:
            handle_verack(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_PING:
            handle_ping(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_PONG:
            handle_pong(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_ADDR:
            handle_addr(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_INV:
            handle_inv(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_BLOCK:
            handle_block(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_TX:
            handle_tx(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_GETBLOCKS:
            handle_getblocks(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_GETDATA:
            handle_getdata(p2p, peer, payload, hdr->length);
            break;
        case FTC_MSG_GETADDR:
            /* Send our known addresses */
            if (p2p->known_addr_count > 0) {
                int count = p2p->known_addr_count;
                if (count > 100) count = 100;
                ftc_p2p_send_addr(p2p, peer, p2p->known_addrs, count);
            }
            break;
        default:
            /* Unknown message - ignore */
            break;
    }
}

/*==============================================================================
 * NETWORK I/O
 *============================================================================*/

static void peer_recv(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    /* Receive data */
    size_t space = peer->recv_capacity - peer->recv_size;
    if (space < 1024) {
        /* Grow buffer */
        size_t new_cap = peer->recv_capacity * 2;
        if (new_cap > FTC_P2P_MAX_MESSAGE_SIZE + sizeof(ftc_msg_header_t)) {
            new_cap = FTC_P2P_MAX_MESSAGE_SIZE + sizeof(ftc_msg_header_t);
        }
        uint8_t* new_buf = realloc(peer->recv_buffer, new_cap);
        if (!new_buf) return;
        peer->recv_buffer = new_buf;
        peer->recv_capacity = new_cap;
        space = new_cap - peer->recv_size;
    }

    int n = recv(peer->socket, (char*)peer->recv_buffer + peer->recv_size, (int)space, 0);
    if (n <= 0) {
        if (n == 0) {
            ftc_p2p_disconnect(p2p, peer, "connection closed");
        } else {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                ftc_p2p_disconnect(p2p, peer, "recv error");
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ftc_p2p_disconnect(p2p, peer, "recv error");
            }
#endif
        }
        return;
    }

    peer->recv_size += n;
    peer->bytes_recv += n;
    p2p->total_bytes_recv += n;

    /* Process complete messages */
    while (peer->recv_size >= sizeof(ftc_msg_header_t)) {
        ftc_msg_header_t* hdr = (ftc_msg_header_t*)peer->recv_buffer;

        /* Verify magic */
        if (hdr->magic != p2p->magic) {
            log_p2p("Invalid magic from %s", format_addr(&peer->addr));
            ftc_p2p_disconnect(p2p, peer, "invalid magic");
            return;
        }

        /* Check message size */
        if (hdr->length > FTC_P2P_MAX_MESSAGE_SIZE) {
            log_p2p("Message too large from %s", format_addr(&peer->addr));
            ftc_p2p_disconnect(p2p, peer, "message too large");
            return;
        }

        /* Check if we have complete message */
        size_t total = sizeof(ftc_msg_header_t) + hdr->length;
        if (peer->recv_size < total) {
            break;  /* Need more data */
        }

        /* Verify checksum */
        uint8_t* payload = peer->recv_buffer + sizeof(ftc_msg_header_t);
        uint32_t checksum = calc_checksum(payload, hdr->length);
        if (checksum != hdr->checksum) {
            log_p2p("Invalid checksum from %s", format_addr(&peer->addr));
            peer->ban_score += 10;
            /* Skip this message */
        } else {
            /* Process message */
            process_message(p2p, peer, hdr, payload);
        }

        /* Remove processed message from buffer */
        memmove(peer->recv_buffer, peer->recv_buffer + total, peer->recv_size - total);
        peer->recv_size -= total;
    }
}

static void peer_send(ftc_p2p_t* p2p, ftc_peer_t* peer) {
    if (peer->send_size == 0) return;

    size_t to_send = peer->send_size - peer->send_offset;
    int n = send(peer->socket, (char*)peer->send_buffer + peer->send_offset, (int)to_send, MSG_NOSIGNAL);

    if (n <= 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            ftc_p2p_disconnect(p2p, peer, "send error");
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ftc_p2p_disconnect(p2p, peer, "send error");
        }
#endif
        return;
    }

    peer->send_offset += n;
    peer->bytes_sent += n;
    p2p->total_bytes_sent += n;

    /* Reset buffer if all sent */
    if (peer->send_offset >= peer->send_size) {
        peer->send_offset = 0;
        peer->send_size = 0;
    }
}

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

ftc_p2p_t* ftc_p2p_new(struct ftc_node* node, uint16_t port, bool listen) {
    if (!init_sockets()) return NULL;

    ftc_p2p_t* p2p = calloc(1, sizeof(ftc_p2p_t));
    if (!p2p) return NULL;

    p2p->port = port ? port : FTC_P2P_PORT;
    p2p->magic = FTC_MAINNET_MAGIC;
    p2p->local_services = FTC_NODE_NETWORK;
    p2p->listen = listen;
    p2p->node = node;
    p2p->listen_socket = FTC_INVALID_SOCKET;
    p2p->next_peer_id = 1;

    /* Initialize known addresses with seeds */
    p2p->known_addr_capacity = 1000;
    p2p->known_addrs = malloc(p2p->known_addr_capacity * sizeof(ftc_netaddr_t));

    return p2p;
}

void ftc_p2p_free(ftc_p2p_t* p2p) {
    if (!p2p) return;

    ftc_p2p_stop(p2p);

    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        if (p2p->peers[i]) {
            peer_free(p2p->peers[i]);
        }
    }

    /* Free orphan blocks */
    for (int i = 0; i < p2p->orphan_count; i++) {
        if (p2p->orphan_blocks[i]) {
            ftc_block_free(p2p->orphan_blocks[i]);
        }
    }

    free(p2p->known_addrs);
    free(p2p);
}

bool ftc_p2p_start(ftc_p2p_t* p2p) {
    p2p->running = true;
    p2p->start_time = time(NULL);
    p2p->initial_sync = true;

    /* Start listening */
    if (p2p->listen) {
        p2p->listen_socket = create_listen_socket(p2p->port);
        if (p2p->listen_socket != FTC_INVALID_SOCKET) {
            log_p2p("Listening on port %d", p2p->port);
        }
    }

    /* Connect to seed nodes */
    for (int i = 0; FTC_SEED_NODES[i].host != NULL; i++) {
        ftc_p2p_connect(p2p, FTC_SEED_NODES[i].host, FTC_SEED_NODES[i].port);
    }

    log_p2p("P2P network started");
    return true;
}

void ftc_p2p_stop(ftc_p2p_t* p2p) {
    p2p->running = false;

    if (p2p->listen_socket != FTC_INVALID_SOCKET) {
        close(p2p->listen_socket);
        p2p->listen_socket = FTC_INVALID_SOCKET;
    }

    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        if (p2p->peers[i]) {
            ftc_p2p_disconnect(p2p, p2p->peers[i], "shutdown");
        }
    }

    log_p2p("P2P network stopped");
}

ftc_peer_t* ftc_p2p_connect(ftc_p2p_t* p2p, const char* host, uint16_t port) {
    if (p2p->outbound_count >= FTC_P2P_MAX_OUTBOUND) {
        return NULL;
    }

    /* Resolve host */
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        log_p2p("Failed to resolve %s", host);
        return NULL;
    }

    /* Create socket */
    ftc_socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == FTC_INVALID_SOCKET) {
        freeaddrinfo(res);
        return NULL;
    }

    set_nonblocking(sock);

    /* Start connection */
    int ret = connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == FTC_SOCKET_ERROR) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
        if (errno != EINPROGRESS) {
#endif
            close(sock);
            return NULL;
        }
    }

    /* Create peer */
    ftc_peer_t* peer = peer_new();
    if (!peer) {
        close(sock);
        return NULL;
    }

    peer->socket = sock;
    peer->inbound = false;
    peer->state = FTC_PEER_CONNECTING;
    peer->connect_time = time(NULL);
    peer->addr.port = port;

    /* Store IP */
    struct sockaddr_in* sin = (struct sockaddr_in*)res->ai_addr;
    ipv4_to_ipv6(sin->sin_addr.s_addr, peer->addr.ip);

    if (!peer_add_to_list(p2p, peer)) {
        peer_free(peer);
        return NULL;
    }

    log_p2p("Connecting to %s:%d", host, port);

    /* Send version immediately */
    ftc_p2p_send_version(p2p, peer);
    peer->state = FTC_PEER_VERSION_SENT;

    return peer;
}

void ftc_p2p_disconnect(ftc_p2p_t* p2p, ftc_peer_t* peer, const char* reason) {
    if (peer->state == FTC_PEER_DISCONNECTED) return;

    log_p2p("Disconnecting %s: %s", format_addr(&peer->addr), reason);

    /* Mark address as failed if it's a connection error (not a clean shutdown) */
    bool is_error = (strcmp(reason, "recv error") == 0 ||
                     strcmp(reason, "send error") == 0 ||
                     strcmp(reason, "connection timeout") == 0 ||
                     strcmp(reason, "handshake timeout") == 0 ||
                     strcmp(reason, "timeout") == 0);
    if (is_error && !peer->inbound) {
        mark_address_failed(p2p, peer->addr.ip, peer->addr.port);
    }

    if (peer->socket != FTC_INVALID_SOCKET) {
        close(peer->socket);
        peer->socket = FTC_INVALID_SOCKET;
    }

    peer->state = FTC_PEER_DISCONNECTED;
    peer_remove_from_list(p2p, peer);
    peer_free(peer);
}

void ftc_p2p_poll(ftc_p2p_t* p2p) {
    if (!p2p->running) return;

    time_t now = time(NULL);

    /* Accept new connections */
    if (p2p->listen_socket != FTC_INVALID_SOCKET &&
        p2p->inbound_count < FTC_P2P_MAX_INBOUND) {

        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ftc_socket_t sock = accept(p2p->listen_socket, (struct sockaddr*)&addr, &addr_len);

        if (sock != FTC_INVALID_SOCKET) {
            set_nonblocking(sock);

            ftc_peer_t* peer = peer_new();
            if (peer) {
                peer->socket = sock;
                peer->inbound = true;
                peer->state = FTC_PEER_CONNECTED;
                peer->connect_time = now;
                peer->addr.port = ntohs(addr.sin_port);
                ipv4_to_ipv6(addr.sin_addr.s_addr, peer->addr.ip);

                if (peer_add_to_list(p2p, peer)) {
                    log_p2p("Accepted connection from %s", format_addr(&peer->addr));
                } else {
                    peer_free(peer);
                }
            } else {
                close(sock);
            }
        }
    }

    /* Process each peer */
    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (!peer) continue;

        /* Check for connection completion */
        if (peer->state == FTC_PEER_CONNECTING) {
            /* Check if connected (by trying to send) */
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len);

            if (error == 0) {
                peer->state = FTC_PEER_VERSION_SENT;
            } else if (now - peer->connect_time > FTC_P2P_HANDSHAKE_TIMEOUT) {
                ftc_p2p_disconnect(p2p, peer, "connection timeout");
                continue;
            }
        }

        /* Receive data */
        peer_recv(p2p, peer);
        if (!p2p->peers[i]) continue;  /* Peer was disconnected */

        /* Send queued data */
        peer_send(p2p, peer);
        if (!p2p->peers[i]) continue;

        /* Check handshake timeout */
        if (peer->state < FTC_PEER_ESTABLISHED &&
            now - peer->connect_time > FTC_P2P_HANDSHAKE_TIMEOUT) {
            ftc_p2p_disconnect(p2p, peer, "handshake timeout");
            continue;
        }

        /* Check inactivity timeout */
        if (peer->state == FTC_PEER_ESTABLISHED &&
            now - peer->last_recv > FTC_P2P_TIMEOUT) {
            ftc_p2p_disconnect(p2p, peer, "timeout");
            continue;
        }

        /* Send pings */
        if (peer->state == FTC_PEER_ESTABLISHED &&
            now - peer->last_ping > FTC_P2P_PING_INTERVAL) {
            ftc_p2p_send_ping(p2p, peer);
        }

        /* Check ban score */
        if (peer->ban_score >= 100) {
            ftc_p2p_disconnect(p2p, peer, "banned");
            continue;
        }
    }

    /* Try to maintain outbound connections */
    if (p2p->outbound_count < FTC_P2P_MAX_OUTBOUND && p2p->known_addr_count > 0) {
        /* Pick random known address */
        int idx = rand() % p2p->known_addr_count;
        ftc_netaddr_t* addr = &p2p->known_addrs[idx];

        /* Check if already connected */
        bool connected = false;
        for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
            if (p2p->peers[i] && memcmp(p2p->peers[i]->addr.ip, addr->ip, 16) == 0) {
                connected = true;
                break;
            }
        }

        if (!connected) {
            char host[64];
            if (memcmp(addr->ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
                snprintf(host, sizeof(host), "%d.%d.%d.%d",
                         addr->ip[12], addr->ip[13], addr->ip[14], addr->ip[15]);
                ftc_p2p_connect(p2p, host, addr->port);
            }
        }
    }
}

int ftc_p2p_peer_count(ftc_p2p_t* p2p) {
    int count = 0;
    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        if (p2p->peers[i] && p2p->peers[i]->state == FTC_PEER_ESTABLISHED) {
            count++;
        }
    }
    return count;
}

void ftc_p2p_broadcast_block(ftc_p2p_t* p2p, const ftc_block_t* block) {
    ftc_inv_t inv;
    inv.type = FTC_INV_BLOCK;
    ftc_block_hash(block, inv.hash);

    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (peer && peer->state == FTC_PEER_ESTABLISHED) {
            ftc_p2p_send_inv(p2p, peer, &inv, 1);
        }
    }
}

void ftc_p2p_broadcast_tx(ftc_p2p_t* p2p, const ftc_tx_t* tx) {
    ftc_inv_t inv;
    inv.type = FTC_INV_TX;
    ftc_tx_hash(tx, inv.hash);

    for (int i = 0; i < FTC_P2P_MAX_PEERS; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (peer && peer->state == FTC_PEER_ESTABLISHED && peer->relay) {
            ftc_p2p_send_inv(p2p, peer, &inv, 1);
        }
    }
}

bool ftc_p2p_sync_blocks(ftc_p2p_t* p2p) {
    if (!p2p->sync_peer) return false;

    ftc_node_t* node = (ftc_node_t*)p2p->node;
    if (!node) return false;

    /* Build block locator */
    ftc_hash256_t locator[10];
    int locator_count = 0;

    int height = node->chain->block_count - 1;
    int step = 1;

    while (height >= 0 && locator_count < 10) {
        ftc_block_hash(node->chain->blocks[height], locator[locator_count++]);
        if (height == 0) break;
        height -= step;
        if (locator_count > 3) step *= 2;
        if (height < 0) height = 0;
    }

    /* Zero stop hash = get as many as possible */
    ftc_hash256_t stop_hash = {0};

    return ftc_p2p_send_getblocks(p2p, p2p->sync_peer, locator, locator_count, stop_hash);
}

void ftc_p2p_add_address(ftc_p2p_t* p2p, const ftc_netaddr_t* addr) {
    /* Check if already known */
    for (int i = 0; i < p2p->known_addr_count; i++) {
        if (memcmp(p2p->known_addrs[i].ip, addr->ip, 16) == 0 &&
            p2p->known_addrs[i].port == addr->port) {
            /* Update timestamp and reset fail count on successful contact */
            p2p->known_addrs[i].timestamp = addr->timestamp;
            p2p->known_addrs[i].fail_count = 0;
            return;
        }
    }

    /* Add new address */
    if (p2p->known_addr_count >= p2p->known_addr_capacity) {
        int new_cap = p2p->known_addr_capacity * 2;
        ftc_netaddr_t* new_addrs = realloc(p2p->known_addrs, new_cap * sizeof(ftc_netaddr_t));
        if (!new_addrs) return;
        p2p->known_addrs = new_addrs;
        p2p->known_addr_capacity = new_cap;
    }

    ftc_netaddr_t new_addr = *addr;
    new_addr.fail_count = 0;
    p2p->known_addrs[p2p->known_addr_count++] = new_addr;
}

/* Remove address from known addresses */
static void remove_known_address(ftc_p2p_t* p2p, const uint8_t* ip, uint16_t port) {
    for (int i = 0; i < p2p->known_addr_count; i++) {
        if (memcmp(p2p->known_addrs[i].ip, ip, 16) == 0 &&
            p2p->known_addrs[i].port == port) {
            /* Remove by shifting array */
            memmove(&p2p->known_addrs[i], &p2p->known_addrs[i + 1],
                    (p2p->known_addr_count - i - 1) * sizeof(ftc_netaddr_t));
            p2p->known_addr_count--;
            return;
        }
    }
}

/* Mark address as failed, remove if too many failures */
#define FTC_MAX_FAIL_COUNT 3
static void mark_address_failed(ftc_p2p_t* p2p, const uint8_t* ip, uint16_t port) {
    for (int i = 0; i < p2p->known_addr_count; i++) {
        if (memcmp(p2p->known_addrs[i].ip, ip, 16) == 0 &&
            p2p->known_addrs[i].port == port) {
            p2p->known_addrs[i].fail_count++;
            if (p2p->known_addrs[i].fail_count >= FTC_MAX_FAIL_COUNT) {
                log_p2p("Removing unreachable peer %s (failed %d times)",
                        format_addr(&p2p->known_addrs[i]), p2p->known_addrs[i].fail_count);
                remove_known_address(p2p, ip, port);
            }
            return;
        }
    }
}

bool ftc_p2p_save_peers(ftc_p2p_t* p2p, const char* path) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;

    /* Write count */
    uint32_t count = p2p->known_addr_count;
    fwrite(&count, 4, 1, f);

    /* Write addresses */
    for (int i = 0; i < p2p->known_addr_count; i++) {
        fwrite(&p2p->known_addrs[i], sizeof(ftc_netaddr_t), 1, f);
    }

    fclose(f);
    return true;
}

bool ftc_p2p_load_peers(ftc_p2p_t* p2p, const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;

    /* Read count */
    uint32_t count;
    if (fread(&count, 4, 1, f) != 1) {
        fclose(f);
        return false;
    }

    if (count > 10000) count = 10000;  /* Sanity limit */

    /* Read addresses */
    for (uint32_t i = 0; i < count; i++) {
        ftc_netaddr_t addr;
        if (fread(&addr, sizeof(ftc_netaddr_t), 1, f) != 1) break;
        ftc_p2p_add_address(p2p, &addr);
    }

    fclose(f);
    log_p2p("Loaded %d peers from %s", p2p->known_addr_count, path);
    return true;
}
