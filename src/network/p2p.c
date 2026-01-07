/**
 * FTC P2P Network Implementation
 *
 * Cross-platform peer-to-peer networking
 */

#include "p2p.h"
#include "protocol.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#endif

/*==============================================================================
 * PLATFORM UTILITIES
 *============================================================================*/

static bool g_winsock_initialized = false;

static bool init_network(void)
{
#ifdef _WIN32
    if (!g_winsock_initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            return false;
        }
        g_winsock_initialized = true;
    }
#endif
    return true;
}

static void close_socket(ftc_socket_t sock)
{
    if (sock != FTC_INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
}

static bool set_nonblocking(ftc_socket_t sock)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static int get_socket_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static bool is_would_block(int err)
{
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
#else
    return err == EWOULDBLOCK || err == EINPROGRESS || err == EAGAIN;
#endif
}

int64_t ftc_time_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (int64_t)((time - 116444736000000000ULL) / 10000);
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/*==============================================================================
 * ADDRESS UTILITIES
 *============================================================================*/

bool ftc_parse_address(const char* str, uint16_t port, ftc_net_addr_t* addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->port = port;
    addr->services = 1;  /* NODE_NETWORK */

    /* Try IPv4 */
    struct in_addr ipv4;
    if (inet_pton(AF_INET, str, &ipv4) == 1) {
        /* Store as IPv4-mapped IPv6 */
        memset(addr->ip, 0, 10);
        addr->ip[10] = 0xff;
        addr->ip[11] = 0xff;
        memcpy(addr->ip + 12, &ipv4, 4);
        return true;
    }

    /* Try IPv6 */
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, str, &ipv6) == 1) {
        memcpy(addr->ip, &ipv6, 16);
        return true;
    }

    return false;
}

void ftc_format_address(const ftc_net_addr_t* addr, char* buf, size_t len)
{
    /* Check if IPv4-mapped */
    bool is_ipv4 = (memcmp(addr->ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0);

    if (is_ipv4) {
        snprintf(buf, len, "%d.%d.%d.%d:%d",
                 addr->ip[12], addr->ip[13], addr->ip[14], addr->ip[15],
                 addr->port);
    } else {
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, addr->ip, ipv6, sizeof(ipv6));
        snprintf(buf, len, "[%s]:%d", ipv6, addr->port);
    }
}

/*==============================================================================
 * PEER MANAGEMENT
 *============================================================================*/

static ftc_peer_t* peer_new(void)
{
    ftc_peer_t* peer = (ftc_peer_t*)calloc(1, sizeof(ftc_peer_t));
    if (!peer) return NULL;

    peer->socket = FTC_INVALID_SOCKET;
    peer->state = FTC_PEER_DISCONNECTED;
    return peer;
}

static void peer_free(ftc_peer_t* peer)
{
    if (!peer) return;
    close_socket(peer->socket);
    free(peer);
}

static ftc_peer_t* find_peer_slot(ftc_p2p_t* p2p)
{
    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        if (p2p->peers[i] == NULL) {
            ftc_peer_t* peer = peer_new();
            if (peer) {
                p2p->peers[i] = peer;
                p2p->peer_count++;
            }
            return peer;
        }
    }
    return NULL;
}

static void remove_peer(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        if (p2p->peers[i] == peer) {
            if (peer->direction == FTC_PEER_OUTBOUND) {
                p2p->outbound_count--;
            } else {
                p2p->inbound_count--;
            }
            peer_free(peer);
            p2p->peers[i] = NULL;
            p2p->peer_count--;
            break;
        }
    }
}

/*==============================================================================
 * P2P MANAGER
 *============================================================================*/

ftc_p2p_t* ftc_p2p_new(void)
{
    if (!init_network()) {
        return NULL;
    }

    ftc_p2p_t* p2p = (ftc_p2p_t*)calloc(1, sizeof(ftc_p2p_t));
    if (!p2p) return NULL;

    p2p->listen_socket = FTC_INVALID_SOCKET;
    p2p->local_services = 1;  /* NODE_NETWORK */

    /* Generate random nonce */
    ftc_random_bytes((uint8_t*)&p2p->local_nonce, 8);

    return p2p;
}

void ftc_p2p_free(ftc_p2p_t* p2p)
{
    if (!p2p) return;

    ftc_p2p_stop(p2p);

    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        if (p2p->peers[i]) {
            peer_free(p2p->peers[i]);
        }
    }

    if (p2p->seed_nodes) {
        for (int i = 0; i < p2p->seed_count; i++) {
            free((void*)p2p->seed_nodes[i]);
        }
        free(p2p->seed_nodes);
    }

    free(p2p);
}

void ftc_p2p_set_callbacks(ftc_p2p_t* p2p, ftc_p2p_callbacks_t* callbacks, void* user_data)
{
    p2p->callbacks = callbacks;
    p2p->user_data = user_data;
}

void ftc_p2p_add_seed(ftc_p2p_t* p2p, const char* host)
{
    p2p->seed_nodes = (const char**)realloc(p2p->seed_nodes, (p2p->seed_count + 1) * sizeof(char*));
    p2p->seed_nodes[p2p->seed_count] = strdup(host);
    p2p->seed_count++;
}

bool ftc_p2p_start(ftc_p2p_t* p2p, uint16_t port)
{
    if (p2p->listening) return true;

    p2p->listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (p2p->listen_socket == FTC_INVALID_SOCKET) {
        return false;
    }

    /* Allow address reuse */
    int opt = 1;
#ifdef _WIN32
    setsockopt(p2p->listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(p2p->listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(p2p->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close_socket(p2p->listen_socket);
        p2p->listen_socket = FTC_INVALID_SOCKET;
        return false;
    }

    if (listen(p2p->listen_socket, 10) != 0) {
        close_socket(p2p->listen_socket);
        p2p->listen_socket = FTC_INVALID_SOCKET;
        return false;
    }

    set_nonblocking(p2p->listen_socket);
    p2p->listen_port = port;
    p2p->listening = true;
    p2p->running = true;

    return true;
}

void ftc_p2p_stop(ftc_p2p_t* p2p)
{
    p2p->running = false;

    if (p2p->listen_socket != FTC_INVALID_SOCKET) {
        close_socket(p2p->listen_socket);
        p2p->listen_socket = FTC_INVALID_SOCKET;
    }
    p2p->listening = false;

    /* Disconnect all peers */
    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        if (p2p->peers[i]) {
            ftc_p2p_disconnect(p2p, p2p->peers[i]);
        }
    }
}

void ftc_p2p_set_height(ftc_p2p_t* p2p, uint32_t height)
{
    p2p->best_height = height;
}

void ftc_p2p_connect_all_seeds(ftc_p2p_t* p2p)
{
    if (!p2p || p2p->seed_count == 0) return;

    for (int i = 0; i < p2p->seed_count && p2p->outbound_count < FTC_MAX_OUTBOUND; i++) {
        ftc_p2p_connect(p2p, p2p->seed_nodes[i], FTC_P2P_PORT);
    }
}

/*==============================================================================
 * CONNECTION MANAGEMENT
 *============================================================================*/

ftc_peer_t* ftc_p2p_connect(ftc_p2p_t* p2p, const char* host, uint16_t port)
{
    if (p2p->outbound_count >= FTC_MAX_OUTBOUND) {
        return NULL;
    }

    /* Resolve hostname */
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        return NULL;
    }

    ftc_peer_t* peer = find_peer_slot(p2p);
    if (!peer) {
        freeaddrinfo(result);
        return NULL;
    }

    peer->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peer->socket == FTC_INVALID_SOCKET) {
        remove_peer(p2p, peer);
        freeaddrinfo(result);
        return NULL;
    }

    set_nonblocking(peer->socket);

    /* Store address info */
    struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, peer->ip_str, sizeof(peer->ip_str));
    ftc_parse_address(peer->ip_str, port, &peer->addr);

    peer->direction = FTC_PEER_OUTBOUND;
    peer->state = FTC_PEER_CONNECTING;
    peer->connect_time = ftc_time_ms();
    p2p->outbound_count++;

    /* Connect (non-blocking) */
    int ret = connect(peer->socket, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (ret != 0) {
        int err = get_socket_error();
        if (!is_would_block(err)) {
            remove_peer(p2p, peer);
            return NULL;
        }
    }

    return peer;
}

void ftc_p2p_disconnect(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    if (!peer) return;

    if (p2p->callbacks && p2p->callbacks->on_peer_disconnected) {
        p2p->callbacks->on_peer_disconnected(p2p, peer);
    }

    remove_peer(p2p, peer);
}

/*==============================================================================
 * MESSAGE SENDING
 *============================================================================*/

bool ftc_peer_send(ftc_peer_t* peer, const uint8_t* data, size_t len)
{
    if (!peer || peer->socket == FTC_INVALID_SOCKET) return false;

    size_t sent = 0;
    while (sent < len) {
        int ret = send(peer->socket, (const char*)(data + sent), (int)(len - sent), 0);
        if (ret <= 0) {
            int err = get_socket_error();
            if (is_would_block(err)) {
                continue;  /* Retry */
            }
            return false;
        }
        sent += ret;
    }

    peer->bytes_sent += len;
    peer->last_send = ftc_time_ms();
    return true;
}

bool ftc_peer_send_version(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    ftc_version_msg_t version;
    memset(&version, 0, sizeof(version));

    version.version = FTC_PROTOCOL_VERSION;
    version.services = p2p->local_services;
    version.timestamp = time(NULL);
    version.addr_recv = peer->addr;
    version.nonce = p2p->local_nonce;
    strncpy(version.user_agent, FTC_USER_AGENT, sizeof(version.user_agent) - 1);
    version.start_height = p2p->best_height;
    version.relay = 1;

    uint8_t msg[256];
    size_t len = ftc_msg_version_build(&version, msg, sizeof(msg));
    if (len == 0) return false;

    peer->state = FTC_PEER_VERSION_SENT;
    return ftc_peer_send(peer, msg, len);
}

bool ftc_peer_send_verack(ftc_peer_t* peer)
{
    uint8_t msg[32];
    size_t len = ftc_msg_verack_build(msg, sizeof(msg));
    return ftc_peer_send(peer, msg, len);
}

bool ftc_peer_send_ping(ftc_peer_t* peer)
{
    ftc_random_bytes((uint8_t*)&peer->ping_nonce, 8);
    peer->last_ping = ftc_time_ms();

    uint8_t msg[32];
    size_t len = ftc_msg_ping_build(peer->ping_nonce, msg, sizeof(msg));
    return ftc_peer_send(peer, msg, len);
}

bool ftc_peer_send_pong(ftc_peer_t* peer, uint64_t nonce)
{
    uint8_t msg[32];
    size_t len = ftc_msg_pong_build(nonce, msg, sizeof(msg));
    return ftc_peer_send(peer, msg, len);
}

bool ftc_peer_send_getaddr(ftc_peer_t* peer)
{
    /* DISABLED: No peer address exchange - use DNS seeds only */
    (void)peer;
    return true;
}

bool ftc_peer_send_addr(ftc_peer_t* peer, const ftc_net_addr_t* addrs, size_t count)
{
    /* DISABLED: No peer address exchange - use DNS seeds only */
    (void)peer;
    (void)addrs;
    (void)count;
    return true;
}

bool ftc_peer_send_inv(ftc_peer_t* peer, const ftc_inv_t* inv, size_t count)
{
    size_t buf_size = 24 + 9 + count * 36;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_inv_build(inv, count, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

bool ftc_peer_send_getdata(ftc_peer_t* peer, const ftc_inv_t* inv, size_t count)
{
    size_t buf_size = 24 + 9 + count * 36;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_getdata_build(inv, count, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

bool ftc_peer_send_block(ftc_peer_t* peer, const ftc_block_t* block)
{
    size_t block_size = ftc_block_serialize(block, NULL, 0);
    size_t buf_size = 24 + block_size;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_block_build(block, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

bool ftc_peer_send_tx(ftc_peer_t* peer, const ftc_tx_t* tx)
{
    size_t tx_size = ftc_tx_serialize(tx, NULL, 0);
    size_t buf_size = 24 + tx_size;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_tx_build(tx, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

bool ftc_peer_send_getheaders(ftc_peer_t* peer, const ftc_hash256_t* locator, size_t count, const ftc_hash256_t stop_hash)
{
    size_t buf_size = 24 + 4 + 9 + count * 32 + 32;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_getheaders_build(locator, count, stop_hash, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

bool ftc_peer_send_headers(ftc_peer_t* peer, const ftc_block_header_t* headers, size_t count)
{
    size_t buf_size = 24 + 9 + count * 81;
    uint8_t* msg = (uint8_t*)malloc(buf_size);
    if (!msg) return false;

    size_t len = ftc_msg_headers_build(headers, count, msg, buf_size);
    bool ok = ftc_peer_send(peer, msg, len);
    free(msg);
    return ok;
}

/*==============================================================================
 * BROADCAST
 *============================================================================*/

void ftc_p2p_broadcast_block(ftc_p2p_t* p2p, const ftc_block_t* block)
{
    ftc_hash256_t hash;
    ftc_block_hash(block, hash);

    ftc_inv_t inv;
    inv.type = FTC_INV_BLOCK;
    memcpy(inv.hash, hash, 32);

    ftc_p2p_broadcast_inv(p2p, &inv, 1);
}

void ftc_p2p_broadcast_tx(ftc_p2p_t* p2p, const ftc_tx_t* tx)
{
    ftc_hash256_t hash;
    ftc_tx_hash(tx, hash);

    ftc_inv_t inv;
    inv.type = FTC_INV_TX;
    memcpy(inv.hash, hash, 32);

    ftc_p2p_broadcast_inv(p2p, &inv, 1);
}

void ftc_p2p_broadcast_inv(ftc_p2p_t* p2p, const ftc_inv_t* inv, size_t count)
{
    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (peer && peer->state >= FTC_PEER_HANDSHAKED) {
            ftc_peer_send_inv(peer, inv, count);
        }
    }
}

/*==============================================================================
 * MESSAGE PROCESSING
 *============================================================================*/

static void process_version(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len < 85) return;

    size_t pos = 0;

    /* Version */
    peer->version = (uint32_t)payload[pos] |
                    ((uint32_t)payload[pos + 1] << 8) |
                    ((uint32_t)payload[pos + 2] << 16) |
                    ((uint32_t)payload[pos + 3] << 24);
    pos += 4;

    /* Services */
    peer->services = 0;
    for (int i = 0; i < 8; i++) {
        peer->services |= ((uint64_t)payload[pos + i] << (i * 8));
    }
    pos += 8;

    /* Skip timestamp */
    pos += 8;

    /* Skip addresses */
    pos += 26 + 26;

    /* Nonce */
    peer->nonce = 0;
    for (int i = 0; i < 8; i++) {
        peer->nonce |= ((uint64_t)payload[pos + i] << (i * 8));
    }
    pos += 8;

    /* Check for self-connection */
    if (peer->nonce == p2p->local_nonce) {
        peer->disconnect_requested = true;
        return;
    }

    /* User agent (varint + string) */
    uint64_t ua_len;
    size_t varint_size = ftc_varint_decode(payload + pos, len - pos, &ua_len);
    pos += varint_size;

    /* Bounds check: ensure we don't read past payload */
    if (ua_len > 0 && ua_len < sizeof(peer->user_agent) && pos + ua_len <= len) {
        memcpy(peer->user_agent, payload + pos, ua_len);
        peer->user_agent[ua_len] = '\0';
    } else if (ua_len >= sizeof(peer->user_agent) || pos + ua_len > len) {
        /* Truncate or skip if invalid */
        size_t copy_len = (len > pos) ? (len - pos) : 0;
        if (copy_len > sizeof(peer->user_agent) - 1) {
            copy_len = sizeof(peer->user_agent) - 1;
        }
        if (copy_len > 0) {
            memcpy(peer->user_agent, payload + pos, copy_len);
        }
        peer->user_agent[copy_len] = '\0';
    }
    pos += ua_len;

    /* Start height */
    if (pos + 4 <= len) {
        peer->start_height = (uint32_t)payload[pos] |
                             ((uint32_t)payload[pos + 1] << 8) |
                             ((uint32_t)payload[pos + 2] << 16) |
                             ((uint32_t)payload[pos + 3] << 24);
        pos += 4;
    }

    /* Relay */
    if (pos < len) {
        peer->relay = payload[pos] != 0;
    }

    /* Send verack */
    ftc_peer_send_verack(peer);

    /* For inbound, send our version now. For outbound, we already sent it. */
    if (peer->direction == FTC_PEER_INBOUND) {
        ftc_peer_send_version(p2p, peer);
        peer->state = FTC_PEER_VERSION_SENT;
    }

    /* If we've sent our version, check if handshake is complete */
    if (peer->state == FTC_PEER_VERSION_SENT) {
        peer->state = FTC_PEER_HANDSHAKED;

        if (p2p->callbacks && p2p->callbacks->on_peer_connected) {
            p2p->callbacks->on_peer_connected(p2p, peer);
        }
    }
    /* If already handshaked (version came after verack), still trigger callback with correct height */
    else if (peer->state == FTC_PEER_HANDSHAKED) {
        if (p2p->callbacks && p2p->callbacks->on_peer_connected) {
            p2p->callbacks->on_peer_connected(p2p, peer);
        }
    }
}

static void process_verack(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    if (peer->state == FTC_PEER_VERSION_SENT) {
        peer->state = FTC_PEER_HANDSHAKED;

        if (p2p->callbacks && p2p->callbacks->on_peer_connected) {
            p2p->callbacks->on_peer_connected(p2p, peer);
        }
    }
}

static void process_ping(ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len >= 8) {
        uint64_t nonce = 0;
        for (int i = 0; i < 8; i++) {
            nonce |= ((uint64_t)payload[i] << (i * 8));
        }
        ftc_peer_send_pong(peer, nonce);
    }
}

static void process_pong(ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len >= 8) {
        uint64_t nonce = 0;
        for (int i = 0; i < 8; i++) {
            nonce |= ((uint64_t)payload[i] << (i * 8));
        }

        if (nonce == peer->ping_nonce) {
            peer->ping_time = ftc_time_ms() - peer->last_ping;
        }
    }
}

static void process_inv(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len < 1) return;

    uint64_t count;
    size_t pos = ftc_varint_decode(payload, len, &count);

    if (count > FTC_MAX_INV_COUNT || pos + count * 36 > len) return;

    ftc_inv_t* inv = (ftc_inv_t*)malloc(count * sizeof(ftc_inv_t));
    if (!inv) return;

    for (size_t i = 0; i < count; i++) {
        inv[i].type = (uint32_t)payload[pos] |
                      ((uint32_t)payload[pos + 1] << 8) |
                      ((uint32_t)payload[pos + 2] << 16) |
                      ((uint32_t)payload[pos + 3] << 24);
        pos += 4;
        memcpy(inv[i].hash, payload + pos, 32);
        pos += 32;
    }

    if (p2p->callbacks && p2p->callbacks->on_inv) {
        p2p->callbacks->on_inv(p2p, peer, inv, (size_t)count);
    }

    free(inv);
}

static void process_block(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    ftc_block_t* block = ftc_block_deserialize(payload, len);
    if (!block) return;

    if (p2p->callbacks && p2p->callbacks->on_block) {
        p2p->callbacks->on_block(p2p, peer, block);
    }

    ftc_block_free(block);
}

static void process_tx(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    size_t consumed;
    ftc_tx_t* tx = ftc_tx_deserialize(payload, len, &consumed);
    if (!tx) return;

    if (p2p->callbacks && p2p->callbacks->on_tx) {
        p2p->callbacks->on_tx(p2p, peer, tx);
    }

    ftc_tx_free(tx);
}

static void process_getdata(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len < 1) return;

    uint64_t count;
    size_t pos = ftc_varint_decode(payload, len, &count);

    if (count > FTC_MAX_INV_COUNT || pos + count * 36 > len) return;

    ftc_inv_t* inv = (ftc_inv_t*)malloc(count * sizeof(ftc_inv_t));
    if (!inv) return;

    for (size_t i = 0; i < count; i++) {
        inv[i].type = (uint32_t)payload[pos] |
                      ((uint32_t)payload[pos + 1] << 8) |
                      ((uint32_t)payload[pos + 2] << 16) |
                      ((uint32_t)payload[pos + 3] << 24);
        pos += 4;
        memcpy(inv[i].hash, payload + pos, 32);
        pos += 32;
    }

    if (p2p->callbacks && p2p->callbacks->on_getdata) {
        p2p->callbacks->on_getdata(p2p, peer, inv, (size_t)count);
    }

    free(inv);
}

static void process_headers(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len < 1) return;

    uint64_t count;
    size_t pos = ftc_varint_decode(payload, len, &count);

    if (count > FTC_MAX_HEADERS_COUNT || pos + count * 81 > len) return;

    ftc_block_header_t* headers = (ftc_block_header_t*)malloc(count * sizeof(ftc_block_header_t));
    if (!headers) return;

    for (size_t i = 0; i < count; i++) {
        ftc_block_header_deserialize(payload + pos, &headers[i]);
        pos += 81;  /* 80 header + 1 tx_count */
    }

    if (p2p->callbacks && p2p->callbacks->on_headers) {
        p2p->callbacks->on_headers(p2p, peer, headers, (size_t)count);
    }

    free(headers);
}

static void process_addr(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    /* DISABLED: No peer address exchange - use DNS seeds only for node discovery */
    (void)p2p;
    (void)peer;
    (void)payload;
    (void)len;
}

static void process_getheaders(ftc_p2p_t* p2p, ftc_peer_t* peer, const uint8_t* payload, size_t len)
{
    if (len < 4) return;

    /* Parse version (4 bytes, little-endian) */
    size_t pos = 4;

    /* Parse locator count (varint) */
    uint64_t count;
    pos += ftc_varint_decode(payload + pos, len - pos, &count);

    if (count == 0 || count > 2000 || pos + count * 32 + 32 > len) return;

    /* Parse locator hashes */
    ftc_hash256_t* locator = (ftc_hash256_t*)malloc(count * sizeof(ftc_hash256_t));
    if (!locator) return;

    for (size_t i = 0; i < count; i++) {
        memcpy(locator[i], payload + pos, 32);
        pos += 32;
    }

    /* Parse stop hash */
    ftc_hash256_t stop_hash;
    memcpy(stop_hash, payload + pos, 32);

    if (p2p->callbacks && p2p->callbacks->on_getheaders) {
        p2p->callbacks->on_getheaders(p2p, peer, locator, (size_t)count, stop_hash);
    }

    free(locator);
}

static void process_message(ftc_p2p_t* p2p, ftc_peer_t* peer, const ftc_msg_header_t* header, const uint8_t* payload)
{
    ftc_msg_type_t type = ftc_msg_string_to_type(header->command);

    switch (type) {
        case FTC_MSG_VERSION:
            process_version(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_VERACK:
            process_verack(p2p, peer);
            break;
        case FTC_MSG_PING:
            process_ping(peer, payload, header->length);
            break;
        case FTC_MSG_PONG:
            process_pong(peer, payload, header->length);
            break;
        case FTC_MSG_INV:
            process_inv(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_BLOCK:
            process_block(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_TX:
            process_tx(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_GETDATA:
            process_getdata(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_HEADERS:
            process_headers(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_ADDR:
            process_addr(p2p, peer, payload, header->length);
            break;
        case FTC_MSG_GETADDR:
            /* DISABLED: No peer address exchange - use DNS seeds only */
            break;
        case FTC_MSG_GETHEADERS:
            process_getheaders(p2p, peer, payload, header->length);
            break;
        default:
            break;
    }
}

static void handle_peer_data(ftc_p2p_t* p2p, ftc_peer_t* peer)
{
    /* Try to receive more data */
    size_t space = sizeof(peer->recv_buf) - peer->recv_len;
    if (space > 0) {
        int ret = recv(peer->socket, (char*)(peer->recv_buf + peer->recv_len), (int)space, 0);
        if (ret > 0) {
            peer->recv_len += ret;
            peer->bytes_recv += ret;
            peer->last_recv = ftc_time_ms();
        } else if (ret == 0) {
            /* Connection closed */
            peer->disconnect_requested = true;
            return;
        } else {
            int err = get_socket_error();
            if (!is_would_block(err)) {
                peer->disconnect_requested = true;
                return;
            }
        }
    }

    /* Process complete messages */
    while (peer->recv_len >= 24) {
        ftc_msg_header_t header;
        if (!ftc_msg_header_deserialize(peer->recv_buf, &header)) {
            /* Invalid magic - disconnect */
            peer->disconnect_requested = true;
            return;
        }

        if (header.length > FTC_MAX_MESSAGE_SIZE) {
            peer->disconnect_requested = true;
            return;
        }

        size_t msg_size = 24 + header.length;
        if (peer->recv_len < msg_size) {
            break;  /* Wait for more data */
        }

        /* Verify checksum */
        if (header.length > 0) {
            uint32_t checksum = ftc_msg_checksum(peer->recv_buf + 24, header.length);
            if (checksum != header.checksum) {
                peer->disconnect_requested = true;
                return;
            }
        }

        /* Process message */
        process_message(p2p, peer, &header, peer->recv_buf + 24);

        /* Remove processed message from buffer */
        memmove(peer->recv_buf, peer->recv_buf + msg_size, peer->recv_len - msg_size);
        peer->recv_len -= msg_size;
    }
}

/*==============================================================================
 * MAIN POLL LOOP
 *============================================================================*/

void ftc_p2p_poll(ftc_p2p_t* p2p, int timeout_ms)
{
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    ftc_socket_t max_fd = 0;

    /* Add listen socket */
    if (p2p->listen_socket != FTC_INVALID_SOCKET) {
        FD_SET(p2p->listen_socket, &read_fds);
        if (p2p->listen_socket > max_fd) max_fd = p2p->listen_socket;
    }

    /* Add peer sockets */
    for (int i = 0; i < FTC_MAX_PEERS; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (!peer || peer->socket == FTC_INVALID_SOCKET) continue;

        if (peer->state == FTC_PEER_CONNECTING) {
            FD_SET(peer->socket, &write_fds);
        } else {
            FD_SET(peer->socket, &read_fds);
        }

        if (peer->socket > max_fd) max_fd = peer->socket;
    }

    /* Select with timeout */
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select((int)(max_fd + 1), &read_fds, &write_fds, NULL, &tv);

    /* Periodic maintenance - runs every poll, even on timeout */
    int64_t now = ftc_time_ms();
    if (now - p2p->last_peer_check > 5000) {
        p2p->last_peer_check = now;

        /* Try to connect to seed nodes if we have no outbound connections */
        if (p2p->outbound_count < FTC_MAX_OUTBOUND && p2p->seed_count > 0) {
            int idx = rand() % p2p->seed_count;
            ftc_p2p_connect(p2p, p2p->seed_nodes[idx], FTC_P2P_PORT);
        }

        /* Peer maintenance */
        for (int i = 0; i < FTC_MAX_PEERS; i++) {
            ftc_peer_t* peer = p2p->peers[i];
            if (!peer) continue;

            /* Connection timeout */
            if (peer->state == FTC_PEER_CONNECTING &&
                now - peer->connect_time > FTC_CONNECT_TIMEOUT) {
                ftc_p2p_disconnect(p2p, peer);
                continue;
            }

            /* Handshake timeout */
            if (peer->state < FTC_PEER_HANDSHAKED &&
                now - peer->connect_time > FTC_HANDSHAKE_TIMEOUT) {
                ftc_p2p_disconnect(p2p, peer);
                continue;
            }

            /* Ping/timeout for active peers */
            if (peer->state >= FTC_PEER_HANDSHAKED) {
                if (now - peer->last_recv > FTC_PEER_TIMEOUT) {
                    ftc_p2p_disconnect(p2p, peer);
                    continue;
                }

                if (now - peer->last_ping > FTC_PING_INTERVAL) {
                    ftc_peer_send_ping(peer);
                }
            }
        }
    }

    if (ret <= 0) return;

    /* Accept new connections */
    if (p2p->listen_socket != FTC_INVALID_SOCKET &&
        FD_ISSET(p2p->listen_socket, &read_fds)) {

        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ftc_socket_t client = accept(p2p->listen_socket, (struct sockaddr*)&addr, &addr_len);

        if (client != FTC_INVALID_SOCKET && p2p->inbound_count < FTC_MAX_INBOUND) {
            ftc_peer_t* peer = find_peer_slot(p2p);
            if (peer) {
                peer->socket = client;
                peer->direction = FTC_PEER_INBOUND;
                peer->state = FTC_PEER_CONNECTED;
                peer->connect_time = ftc_time_ms();
                p2p->inbound_count++;

                inet_ntop(AF_INET, &addr.sin_addr, peer->ip_str, sizeof(peer->ip_str));
                ftc_parse_address(peer->ip_str, ntohs(addr.sin_port), &peer->addr);

                set_nonblocking(peer->socket);

                /* Inbound: wait for their version first */
            } else {
                close_socket(client);
            }
        } else if (client != FTC_INVALID_SOCKET) {
            close_socket(client);
        }
    }

    /* Process peer events - limit to prevent RPC starvation */
    int peers_processed = 0;
    const int max_peers_per_poll = 50;  /* Process max 50 peers per poll cycle */

    for (int i = 0; i < FTC_MAX_PEERS && peers_processed < max_peers_per_poll; i++) {
        ftc_peer_t* peer = p2p->peers[i];
        if (!peer || peer->socket == FTC_INVALID_SOCKET) continue;

        /* Check for connection completion */
        if (peer->state == FTC_PEER_CONNECTING && FD_ISSET(peer->socket, &write_fds)) {
            int err = 0;
            socklen_t err_len = sizeof(err);
            getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len);

            if (err == 0) {
                peer->state = FTC_PEER_CONNECTED;
                ftc_peer_send_version(p2p, peer);
            } else {
                peer->disconnect_requested = true;
            }
            peers_processed++;
        }

        /* Handle readable */
        if (FD_ISSET(peer->socket, &read_fds)) {
            handle_peer_data(p2p, peer);
            peers_processed++;
        }

        /* Check for disconnect */
        if (peer->disconnect_requested) {
            ftc_p2p_disconnect(p2p, peer);
        }
    }
}
