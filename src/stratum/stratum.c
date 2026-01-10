/**
 * FTC Stratum Server Implementation
 *
 * Stratum mining pool protocol for GPU miners
 */

#include "stratum.h"
#include "../crypto/keccak256.h"
#include "../crypto/keys.h"
#include "../../node/full_node.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close_socket closesocket
#define WOULD_BLOCK (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#define close_socket close
#define WOULD_BLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

/* Forward declarations */
static void stratum_create_job(ftc_stratum_t* stratum);

/*==============================================================================
 * UTILITY FUNCTIONS
 *============================================================================*/

static void bytes_to_hex(const uint8_t* bytes, size_t len, char* out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[bytes[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static void hex_to_bytes(const char* hex, uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

static void bytes_to_hex_reverse(const uint8_t* bytes, size_t len, char* out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[len - 1 - i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[bytes[len - 1 - i] & 0xf];
    }
    out[len * 2] = '\0';
}

static bool set_socket_nonblocking(stratum_socket_t sock)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static void set_socket_options(stratum_socket_t sock)
{
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    /* Disable Nagle's algorithm for low latency */
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
}

/*==============================================================================
 * CLIENT MANAGEMENT
 *============================================================================*/

static stratum_client_t* client_new(stratum_socket_t sock, struct sockaddr_in* addr, uint32_t id)
{
    stratum_client_t* client = calloc(1, sizeof(stratum_client_t));
    if (!client) return NULL;

    client->socket = sock;
    client->addr = *addr;
    client->id = id;
    client->state = STRATUM_CLIENT_CONNECTED;
    client->connect_time = time(NULL);
    client->last_activity = client->connect_time;
    client->difficulty = STRATUM_DEFAULT_DIFFICULTY;
    client->vardiff_time = client->connect_time;

    return client;
}

static void client_free(stratum_client_t* client)
{
    if (!client) return;
    if (client->socket != STRATUM_INVALID_SOCKET) {
        close_socket(client->socket);
    }
    free(client);
}

static bool client_send(stratum_client_t* client, const char* msg)
{
    size_t len = strlen(msg);
    if (client->send_len + len + 1 > STRATUM_SEND_BUFFER_SIZE) {
        return false;
    }

    memcpy(client->send_buffer + client->send_len, msg, len);
    client->send_len += len;
    client->send_buffer[client->send_len++] = '\n';

    return true;
}

static void client_flush(stratum_client_t* client)
{
    if (client->send_offset >= client->send_len) {
        client->send_offset = 0;
        client->send_len = 0;
        return;
    }

    size_t remaining = client->send_len - client->send_offset;
    int sent = send(client->socket, client->send_buffer + client->send_offset, (int)remaining, 0);

    if (sent > 0) {
        client->send_offset += sent;
        if (client->send_offset >= client->send_len) {
            client->send_offset = 0;
            client->send_len = 0;
        }
    }
}

/*==============================================================================
 * STRATUM PROTOCOL HANDLERS
 *============================================================================*/

static void stratum_send_error(stratum_client_t* client, int id, int code, const char* message)
{
    char response[512];
    snprintf(response, sizeof(response),
             "{\"id\":%d,\"result\":null,\"error\":[%d,\"%s\",null]}",
             id, code, message);
    client_send(client, response);
}

static void stratum_send_result(stratum_client_t* client, int id, const char* result)
{
    char response[1024];
    snprintf(response, sizeof(response),
             "{\"id\":%d,\"result\":%s,\"error\":null}",
             id, result);
    client_send(client, response);
}

static void stratum_handle_subscribe(ftc_stratum_t* stratum, stratum_client_t* client, int id, const char* params)
{
    /* Parse user agent from params if present */
    if (params) {
        const char* ua_start = strchr(params, '"');
        if (ua_start) {
            ua_start++;
            const char* ua_end = strchr(ua_start, '"');
            if (ua_end && ua_end - ua_start < (int)sizeof(client->user_agent) - 1) {
                memcpy(client->user_agent, ua_start, ua_end - ua_start);
                client->user_agent[ua_end - ua_start] = '\0';
            }
        }
    }

    /* Generate unique extranonce1 for this client */
    uint32_t en1 = stratum->next_extranonce1++;
    memcpy(client->extranonce1, &en1, STRATUM_EXTRANONCE1_SIZE);
    bytes_to_hex(client->extranonce1, STRATUM_EXTRANONCE1_SIZE, client->extranonce1_hex);

    client->state = STRATUM_CLIENT_SUBSCRIBED;

    /* Response: [[["mining.set_difficulty", "sub_id"], ["mining.notify", "sub_id"]], extranonce1, extranonce2_size] */
    char result[512];
    snprintf(result, sizeof(result),
             "[[[\"%s\",\"%08x\"],[\"%s\",\"%08x\"]],\"%s\",%d]",
             "mining.set_difficulty", client->id,
             "mining.notify", client->id,
             client->extranonce1_hex,
             STRATUM_EXTRANONCE2_SIZE);

    stratum_send_result(client, id, result);

    printf("[STRATUM] Client %u subscribed (%s) extranonce1=%s\n",
           client->id, client->user_agent, client->extranonce1_hex);
}

static void stratum_handle_authorize(ftc_stratum_t* stratum, stratum_client_t* client, int id, const char* params)
{
    (void)stratum;

    /* Parse worker name (address) from params */
    if (params) {
        const char* worker_start = strchr(params, '"');
        if (worker_start) {
            worker_start++;
            const char* worker_end = strchr(worker_start, '"');
            if (worker_end && worker_end - worker_start < (int)sizeof(client->worker_name) - 1) {
                memcpy(client->worker_name, worker_start, worker_end - worker_start);
                client->worker_name[worker_end - worker_start] = '\0';

                /* Extract address from worker name (format: address.worker or just address) */
                char* dot = strchr(client->worker_name, '.');
                if (dot) {
                    size_t addr_len = dot - client->worker_name;
                    memcpy(client->miner_address, client->worker_name, addr_len);
                    client->miner_address[addr_len] = '\0';
                } else {
                    size_t len = strlen(client->worker_name);
                    if (len >= sizeof(client->miner_address)) {
                        len = sizeof(client->miner_address) - 1;
                    }
                    memcpy(client->miner_address, client->worker_name, len);
                    client->miner_address[len] = '\0';
                }
            }
        }
    }

    /* Validate address format (basic check) */
    size_t addr_len = strlen(client->miner_address);
    if (addr_len >= 26 && addr_len <= 62) {
        client->state = STRATUM_CLIENT_AUTHORIZED;
        stratum_send_result(client, id, "true");
        printf("[STRATUM] Client %u authorized as %s\n", client->id, client->miner_address);

        /* If no block template yet (first miner), create job now */
        if (!stratum->current_job.block_template) {
            printf("[STRATUM] First miner connected, creating job...\n");
            stratum_create_job(stratum);
        }
    } else {
        stratum_send_error(client, id, 20, "Invalid worker address");
        printf("[STRATUM] Client %u authorization failed: invalid address '%s'\n",
               client->id, client->miner_address);
    }
}

static void stratum_send_difficulty(ftc_stratum_t* stratum, stratum_client_t* client)
{
    (void)stratum;

    char msg[256];
    snprintf(msg, sizeof(msg),
             "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[%g]}",
             client->difficulty);
    client_send(client, msg);
}

static void stratum_send_job(ftc_stratum_t* stratum, stratum_client_t* client, bool clean)
{
    stratum_job_t* job = &stratum->current_job;
    if (!job->block_template) {
        printf("[STRATUM] Cannot send job - no block template\n");
        return;
    }

    /* Convert hashes to hex (NOT reversed - simplified FTC protocol) */
    char prevhash_hex[65];
    bytes_to_hex(job->prevhash, 32, prevhash_hex);

    /* For FTC, we send merkle_root directly in coinb1 field */
    char coinb1_hex[65];
    bytes_to_hex(job->merkle_root, 32, coinb1_hex);

    /* mining.notify params:
     * [job_id, prevhash, coinb1, coinb2, merkle_branches[], version, nbits, ntime, clean_jobs]
     */
    char msg[2048];
    snprintf(msg, sizeof(msg),
             "{\"id\":null,\"method\":\"mining.notify\","
             "\"params\":[\"%s\",\"%s\",\"%s\",\"\",[],"
             "\"%08x\",\"%08x\",\"%08x\",%s]}",
             job->job_id,
             prevhash_hex,
             coinb1_hex,
             job->version,
             job->nbits,
             job->ntime,
             clean ? "true" : "false");

    client_send(client, msg);
    snprintf(client->current_job_id, sizeof(client->current_job_id), "%s", job->job_id);
    printf("[STRATUM] Sent job %s to client %u\n", job->job_id, client->id);
}

static void stratum_handle_submit(ftc_stratum_t* stratum, stratum_client_t* client, int id, const char* params)
{
    /* Parse submit params: [worker, job_id, extranonce2, ntime, nonce] */
    char job_id[STRATUM_JOB_ID_SIZE + 1] = {0};
    char extranonce2_hex[STRATUM_EXTRANONCE2_SIZE * 2 + 1] = {0};
    char ntime_hex[9] = {0};
    char nonce_hex[9] = {0};

    if (!params) {
        stratum_send_error(client, id, 20, "Missing parameters");
        client->shares_rejected++;
        return;
    }

    /* Simple parsing - find the parameters */
    const char* p = params;
    int field = 0;
    while (*p && field < 5) {
        if (*p == '"') {
            p++;
            const char* start = p;
            while (*p && *p != '"') p++;
            size_t len = p - start;

            switch (field) {
                case 1: /* job_id */
                    if (len <= STRATUM_JOB_ID_SIZE) {
                        memcpy(job_id, start, len);
                    }
                    break;
                case 2: /* extranonce2 */
                    if (len <= STRATUM_EXTRANONCE2_SIZE * 2) {
                        memcpy(extranonce2_hex, start, len);
                    }
                    break;
                case 3: /* ntime */
                    if (len == 8) {
                        memcpy(ntime_hex, start, len);
                    }
                    break;
                case 4: /* nonce */
                    if (len == 8) {
                        memcpy(nonce_hex, start, len);
                    }
                    break;
            }
            field++;
        }
        p++;
    }

    /* Verify job ID matches current job */
    if (strcmp(job_id, stratum->current_job.job_id) != 0) {
        stratum_send_error(client, id, 21, "Job not found (stale)");
        client->shares_rejected++;
        return;
    }

    /* Parse nonce and ntime */
    uint32_t nonce = 0, ntime = 0;
    sscanf(nonce_hex, "%08x", &nonce);
    sscanf(ntime_hex, "%08x", &ntime);

    /* Build block header for verification */
    stratum_job_t* job = &stratum->current_job;
    uint8_t header[80];
    memset(header, 0, 80);

    memcpy(header, &job->version, 4);
    memcpy(header + 4, job->prevhash, 32);
    memcpy(header + 36, job->merkle_root, 32);
    memcpy(header + 68, &ntime, 4);
    memcpy(header + 72, &job->nbits, 4);
    memcpy(header + 76, &nonce, 4);

    /* Hash the header (double Keccak256 like GPU) */
    ftc_hash256_t hash;
    ftc_keccak256_double(header, 80, hash);

    /* Calculate share target from pool difficulty */
    ftc_hash256_t share_target;
    ftc_bits_to_target(0x1e0fffff, share_target);  /* Base diff 1 */

    /* Scale target by difficulty (higher diff = lower target) */
    if (client->difficulty > 1.0) {
        /* Simple scaling - divide target by difficulty */
        double scale = 1.0 / client->difficulty;
        uint64_t* t64 = (uint64_t*)share_target;
        for (int i = 0; i < 4; i++) {
            t64[i] = (uint64_t)(t64[i] * scale);
        }
    }

    /* Check if hash meets share target */
    bool valid_share = true;
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < share_target[i]) break;
        if (hash[i] > share_target[i]) {
            valid_share = false;
            break;
        }
    }

    if (!valid_share) {
        stratum_send_error(client, id, 23, "Low difficulty share");
        client->shares_rejected++;
        return;
    }

    /* Share is valid! */
    client->shares_accepted++;
    client->last_activity = time(NULL);
    stratum->total_shares++;

    /* Track for vardiff */
    client->vardiff_shares++;

    /* Add share to P2Pool */
    if (stratum->p2pool) {
        ftc_p2pool_submit_share(stratum->p2pool, client->miner_address, header, nonce);
    }

    /* Check if this also meets network difficulty (block found!) */
    ftc_hash256_t network_target;
    ftc_bits_to_target(job->nbits, network_target);

    bool is_block = true;
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < network_target[i]) break;
        if (hash[i] > network_target[i]) {
            is_block = false;
            break;
        }
    }

    if (is_block) {
        char hash_hex[65];
        bytes_to_hex(hash, 32, hash_hex);

        printf("[STRATUM] *** BLOCK FOUND by %s! Hash: %s ***\n",
               client->miner_address, hash_hex);

        client->blocks_found++;
        stratum->total_blocks++;

        /* Submit block to node */
        ftc_node_t* node = stratum->node;
        if (node && job->block_template) {
            /* Update block header with winning nonce */
            job->block_template->header.nonce = nonce;
            job->block_template->header.timestamp = ntime;

            /* Submit to blockchain */
            if (ftc_node_submit_block(node, job->block_template)) {
                printf("[STRATUM] Block submitted successfully!\n");

                /* Broadcast new job */
                ftc_stratum_notify_new_block(stratum);
            } else {
                printf("[STRATUM] Block submission failed!\n");
            }
        }
    }

    stratum_send_result(client, id, "true");
}

static void stratum_handle_message(ftc_stratum_t* stratum, stratum_client_t* client, const char* line)
{
    /* Parse JSON-RPC message */
    int id = 0;
    char method[64] = {0};

    /* Find id */
    const char* id_str = strstr(line, "\"id\":");
    if (id_str) {
        id = atoi(id_str + 5);
    }

    /* Find method */
    const char* method_str = strstr(line, "\"method\":\"");
    if (method_str) {
        method_str += 10;
        const char* method_end = strchr(method_str, '"');
        if (method_end && method_end - method_str < (int)sizeof(method)) {
            memcpy(method, method_str, method_end - method_str);
        }
    }

    /* Find params */
    const char* params = strstr(line, "\"params\":");
    if (params) {
        params += 9;
        /* Skip whitespace */
        while (*params && (*params == ' ' || *params == '\t')) params++;
    }

    /* Dispatch */
    if (strcmp(method, "mining.subscribe") == 0) {
        stratum_handle_subscribe(stratum, client, id, params);
        /* Note: Don't send difficulty here - it would stay in client's buffer
         * and interfere with authorize response. Send after authorize instead. */
    } else if (strcmp(method, "mining.authorize") == 0) {
        stratum_handle_authorize(stratum, client, id, params);
        /* Send difficulty and job after authorization */
        if (client->state == STRATUM_CLIENT_AUTHORIZED) {
            stratum_send_difficulty(stratum, client);
            stratum_send_job(stratum, client, true);
        }
    } else if (strcmp(method, "mining.submit") == 0) {
        if (client->state != STRATUM_CLIENT_AUTHORIZED) {
            stratum_send_error(client, id, 24, "Unauthorized");
        } else {
            stratum_handle_submit(stratum, client, id, params);
        }
    } else if (strcmp(method, "mining.hashrate") == 0) {
        /* Optional: client-reported hashrate */
        if (params) {
            client->hashrate = atof(params + 1);  /* Skip '[' */
        }
        stratum_send_result(client, id, "true");
    } else {
        /* Unknown method */
        stratum_send_error(client, id, 20, "Unknown method");
    }

    client->last_activity = time(NULL);
}

/*==============================================================================
 * JOB MANAGEMENT
 *============================================================================*/

static void stratum_create_job(ftc_stratum_t* stratum)
{
    ftc_node_t* node = stratum->node;
    if (!node || !node->chain || node->chain->block_count == 0) return;

    stratum_job_t* job = &stratum->current_job;

    /* Free previous block template */
    if (job->block_template) {
        ftc_block_free(job->block_template);
        job->block_template = NULL;
    }

    /* Generate new job ID */
    snprintf(job->job_id, sizeof(job->job_id), "%08x", stratum->next_job_id++);

    /* Get current chain tip */
    ftc_block_t* tip = node->chain->blocks[node->chain->block_count - 1];

    job->height = node->chain->block_count;
    job->version = 1;  /* Block version */
    ftc_block_hash(tip, job->prevhash);
    job->ntime = (uint32_t)time(NULL);
    job->clean_jobs = true;

    /* Create block template with P2Pool payouts to ALL miners */
    ftc_address_t fallback_addr;
    memset(fallback_addr, 0, sizeof(fallback_addr));

    /* Get first miner address as fallback (in case no shares yet) */
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        if (stratum->clients[i] && stratum->clients[i]->state == STRATUM_CLIENT_AUTHORIZED) {
            ftc_address_decode(stratum->clients[i]->miner_address, fallback_addr, NULL);
            break;
        }
    }

    /* Create base block template */
    job->block_template = ftc_node_create_block_template(node, fallback_addr);
    if (job->block_template) {
        /* Replace coinbase with P2Pool multi-payout coinbase if we have shares */
        if (stratum->p2pool && stratum->p2pool->pplns && stratum->p2pool->pplns->miner_count > 0) {
            uint64_t block_reward = 50 * 100000000ULL;  /* 50 FTC in satoshis */
            uint64_t fees = 0;  /* TODO: calculate from mempool */

            ftc_tx_t* p2pool_coinbase = ftc_p2pool_create_coinbase(
                stratum->p2pool, job->height, block_reward, fees);

            if (p2pool_coinbase) {
                /* Replace the coinbase transaction */
                if (job->block_template->tx_count > 0 && job->block_template->transactions[0]) {
                    ftc_tx_free(job->block_template->transactions[0]);
                }
                job->block_template->transactions[0] = p2pool_coinbase;

                /* Recalculate merkle root */
                ftc_block_merkle_root(job->block_template, job->block_template->header.merkle_root);

                printf("[STRATUM] P2Pool coinbase: %d miners will share reward\n",
                       p2pool_coinbase->output_count);
            }
        }

        /* Get merkle root and bits from block template */
        memcpy(job->merkle_root, job->block_template->header.merkle_root, 32);
        job->nbits = job->block_template->header.bits;
    } else {
        /* No block template - use tip's bits as fallback */
        job->nbits = tip->header.bits;
    }

    printf("[STRATUM] New job %s at height %u (diff target: %08x)\n",
           job->job_id, job->height, job->nbits);
}

/*==============================================================================
 * STRATUM SERVER
 *============================================================================*/

ftc_stratum_t* ftc_stratum_new(struct ftc_node* node, uint16_t port)
{
    ftc_stratum_t* stratum = calloc(1, sizeof(ftc_stratum_t));
    if (!stratum) return NULL;

    stratum->node = node;
    stratum->port = port ? port : STRATUM_DEFAULT_PORT;
    stratum->listen_socket = STRATUM_INVALID_SOCKET;
    stratum->default_difficulty = STRATUM_DEFAULT_DIFFICULTY;
    stratum->vardiff_enabled = true;
    stratum->next_extranonce1 = 1;
    stratum->next_job_id = 1;

    /* Create P2Pool for payout distribution */
    stratum->p2pool = ftc_p2pool_new(node);

    printf("[STRATUM] Server created on port %u\n", stratum->port);

    return stratum;
}

void ftc_stratum_free(ftc_stratum_t* stratum)
{
    if (!stratum) return;

    ftc_stratum_stop(stratum);

    /* Free all clients */
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        if (stratum->clients[i]) {
            client_free(stratum->clients[i]);
            stratum->clients[i] = NULL;
        }
    }

    /* Free job block template */
    if (stratum->current_job.block_template) {
        ftc_block_free(stratum->current_job.block_template);
    }

    /* Free P2Pool */
    if (stratum->p2pool) {
        ftc_p2pool_free(stratum->p2pool);
    }

    free(stratum);
}

bool ftc_stratum_start(ftc_stratum_t* stratum)
{
    if (!stratum || stratum->running) return false;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[STRATUM] WSAStartup failed\n");
        return false;
    }
#endif

    /* Create listening socket */
    stratum->listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (stratum->listen_socket == STRATUM_INVALID_SOCKET) {
        fprintf(stderr, "[STRATUM] Failed to create socket\n");
        return false;
    }

    set_socket_options(stratum->listen_socket);
    set_socket_nonblocking(stratum->listen_socket);

    /* Bind to port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(stratum->port);

    if (bind(stratum->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[STRATUM] Failed to bind to port %u\n", stratum->port);
        close_socket(stratum->listen_socket);
        stratum->listen_socket = STRATUM_INVALID_SOCKET;
        return false;
    }

    if (listen(stratum->listen_socket, 32) < 0) {
        fprintf(stderr, "[STRATUM] Failed to listen\n");
        close_socket(stratum->listen_socket);
        stratum->listen_socket = STRATUM_INVALID_SOCKET;
        return false;
    }

    stratum->running = true;
    stratum->start_time = time(NULL);

    /* Create initial job */
    stratum_create_job(stratum);

    printf("[STRATUM] Server started on port %u\n", stratum->port);

    return true;
}

void ftc_stratum_stop(ftc_stratum_t* stratum)
{
    if (!stratum || !stratum->running) return;

    stratum->running = false;

    /* Close listening socket */
    if (stratum->listen_socket != STRATUM_INVALID_SOCKET) {
        close_socket(stratum->listen_socket);
        stratum->listen_socket = STRATUM_INVALID_SOCKET;
    }

    /* Close all client connections */
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        if (stratum->clients[i]) {
            close_socket(stratum->clients[i]->socket);
            stratum->clients[i]->socket = STRATUM_INVALID_SOCKET;
        }
    }

    printf("[STRATUM] Server stopped\n");
}

void ftc_stratum_poll(ftc_stratum_t* stratum)
{
    if (!stratum || !stratum->running) return;

    /* Accept new connections */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    stratum_socket_t client_sock = accept(stratum->listen_socket,
                                           (struct sockaddr*)&client_addr,
                                           &client_len);

    if (client_sock != STRATUM_INVALID_SOCKET) {
        set_socket_nonblocking(client_sock);
        set_socket_options(client_sock);

        /* Find empty slot */
        int slot = -1;
        for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
            if (!stratum->clients[i]) {
                slot = i;
                break;
            }
        }

        if (slot >= 0) {
            stratum_client_t* client = client_new(client_sock, &client_addr,
                                                   stratum->next_client_id++);
            if (client) {
                stratum->clients[slot] = client;
                stratum->client_count++;
                stratum->total_clients_connected++;

                printf("[STRATUM] Client %u connected from %s:%d\n",
                       client->id,
                       inet_ntoa(client_addr.sin_addr),
                       ntohs(client_addr.sin_port));
            }
        } else {
            /* No slots available */
            close_socket(client_sock);
        }
    }

    time_t now = time(NULL);

    /* Process existing clients */
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        stratum_client_t* client = stratum->clients[i];
        if (!client) continue;

        /* Check for timeout */
        if (now - client->last_activity > STRATUM_TIMEOUT) {
            printf("[STRATUM] Client %u timed out\n", client->id);
            client_free(client);
            stratum->clients[i] = NULL;
            stratum->client_count--;
            continue;
        }

        /* Flush send buffer */
        client_flush(client);

        /* Receive data */
        int available = STRATUM_RECV_BUFFER_SIZE - (int)client->recv_len - 1;
        if (available > 0) {
            int n = recv(client->socket, client->recv_buffer + client->recv_len, available, 0);
            if (n > 0) {
                client->recv_len += n;
                client->recv_buffer[client->recv_len] = '\0';

                /* Process complete lines */
                char* line_start = client->recv_buffer;
                char* newline;
                while ((newline = strchr(line_start, '\n')) != NULL) {
                    *newline = '\0';

                    /* Remove \r if present */
                    if (newline > line_start && *(newline - 1) == '\r') {
                        *(newline - 1) = '\0';
                    }

                    if (*line_start) {
                        stratum_handle_message(stratum, client, line_start);
                    }

                    line_start = newline + 1;
                }

                /* Move remaining data to start of buffer */
                if (line_start > client->recv_buffer) {
                    size_t remaining = client->recv_len - (line_start - client->recv_buffer);
                    memmove(client->recv_buffer, line_start, remaining);
                    client->recv_len = remaining;
                }
            } else if (n == 0) {
                /* Connection closed */
                printf("[STRATUM] Client %u disconnected\n", client->id);
                client_free(client);
                stratum->clients[i] = NULL;
                stratum->client_count--;
                continue;
            }
        }
    }

    /* Vardiff adjustment (every 30 seconds) */
    static time_t last_vardiff = 0;
    if (now - last_vardiff >= 30) {
        last_vardiff = now;

        for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
            stratum_client_t* client = stratum->clients[i];
            if (!client || client->state != STRATUM_CLIENT_AUTHORIZED) continue;

            /* Target: ~10 shares per minute */
            double elapsed = (double)(now - client->vardiff_time);
            if (elapsed > 0 && client->vardiff_shares > 0) {
                double shares_per_min = (client->vardiff_shares / elapsed) * 60.0;

                if (shares_per_min > 20.0 && client->difficulty < STRATUM_MAX_DIFFICULTY) {
                    /* Too many shares, increase difficulty */
                    client->difficulty *= 2.0;
                    if (client->difficulty > STRATUM_MAX_DIFFICULTY)
                        client->difficulty = STRATUM_MAX_DIFFICULTY;
                    stratum_send_difficulty(stratum, client);
                    printf("[STRATUM] Client %u difficulty increased to %g\n",
                           client->id, client->difficulty);
                } else if (shares_per_min < 5.0 && client->difficulty > STRATUM_MIN_DIFFICULTY) {
                    /* Too few shares, decrease difficulty */
                    client->difficulty /= 2.0;
                    if (client->difficulty < STRATUM_MIN_DIFFICULTY)
                        client->difficulty = STRATUM_MIN_DIFFICULTY;
                    stratum_send_difficulty(stratum, client);
                    printf("[STRATUM] Client %u difficulty decreased to %g\n",
                           client->id, client->difficulty);
                }
            }

            client->vardiff_shares = 0;
            client->vardiff_time = now;
        }
    }

    /* Create new job if chain tip changed */
    ftc_node_t* node = stratum->node;
    if (node && node->chain) {
        uint32_t current_height = node->chain->block_count;
        if (current_height != stratum->current_job.height) {
            ftc_stratum_notify_new_block(stratum);
        }
    }
}

void ftc_stratum_notify_new_block(ftc_stratum_t* stratum)
{
    if (!stratum || !stratum->running) return;

    /* Create new job */
    stratum_create_job(stratum);

    /* Broadcast to all authorized clients */
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        stratum_client_t* client = stratum->clients[i];
        if (client && client->state == STRATUM_CLIENT_AUTHORIZED) {
            stratum_send_job(stratum, client, true);
        }
    }

    stratum->last_job_broadcast = time(NULL);
}

int ftc_stratum_get_miner_count(ftc_stratum_t* stratum)
{
    if (!stratum) return 0;

    int count = 0;
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        if (stratum->clients[i] && stratum->clients[i]->state == STRATUM_CLIENT_AUTHORIZED) {
            count++;
        }
    }
    return count;
}

double ftc_stratum_get_hashrate(ftc_stratum_t* stratum)
{
    if (!stratum) return 0.0;

    double total = 0.0;
    for (int i = 0; i < STRATUM_MAX_CLIENTS; i++) {
        if (stratum->clients[i] && stratum->clients[i]->state == STRATUM_CLIENT_AUTHORIZED) {
            total += stratum->clients[i]->hashrate;
        }
    }
    return total;
}

void ftc_stratum_get_stats(ftc_stratum_t* stratum, ftc_stratum_stats_t* stats)
{
    if (!stratum || !stats) return;

    memset(stats, 0, sizeof(*stats));
    stats->total_shares = stratum->total_shares;
    stats->total_blocks = stratum->total_blocks;
    stats->active_miners = ftc_stratum_get_miner_count(stratum);
    stats->pool_hashrate = ftc_stratum_get_hashrate(stratum);
    stats->uptime = time(NULL) - stratum->start_time;
}
