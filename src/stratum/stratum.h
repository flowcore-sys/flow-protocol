/**
 * FTC Stratum Server
 *
 * Mining pool protocol server for GPU miners
 * Implements Stratum protocol (mining.subscribe, mining.authorize, etc.)
 */

#ifndef FTC_STRATUM_H
#define FTC_STRATUM_H

#include "../../include/ftc.h"
#include "../core/block.h"
#include "../p2pool/p2pool.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET stratum_socket_t;
#define STRATUM_INVALID_SOCKET INVALID_SOCKET
#define STRATUM_SOCKET_ERROR SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
typedef int stratum_socket_t;
#define STRATUM_INVALID_SOCKET -1
#define STRATUM_SOCKET_ERROR -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

#define STRATUM_DEFAULT_PORT        3333
#define STRATUM_MAX_CLIENTS         256
#define STRATUM_MAX_MESSAGE_SIZE    16384
#define STRATUM_RECV_BUFFER_SIZE    32768
#define STRATUM_SEND_BUFFER_SIZE    32768
#define STRATUM_EXTRANONCE1_SIZE    4
#define STRATUM_EXTRANONCE2_SIZE    4
#define STRATUM_JOB_ID_SIZE         8
#define STRATUM_PING_INTERVAL       30      /* Seconds between pings */
#define STRATUM_TIMEOUT             120     /* Disconnect after 2 min silence */
#define STRATUM_DEFAULT_DIFFICULTY  64.0        /* Starting difficulty - vardiff will adjust */
#define STRATUM_MIN_DIFFICULTY      1.0         /* Minimum difficulty */
#define STRATUM_MAX_DIFFICULTY      1e15        /* No practical limit (supports 1 PH/s+) */

/*==============================================================================
 * STRATUM CLIENT (connected miner)
 *============================================================================*/

typedef enum {
    STRATUM_CLIENT_CONNECTED    = 0,
    STRATUM_CLIENT_SUBSCRIBED   = 1,
    STRATUM_CLIENT_AUTHORIZED   = 2,
} stratum_client_state_t;

typedef struct stratum_client {
    /* Socket */
    stratum_socket_t        socket;
    struct sockaddr_in      addr;

    /* State */
    stratum_client_state_t  state;
    time_t                  connect_time;
    time_t                  last_activity;

    /* Worker info */
    char                    worker_name[128];
    char                    miner_address[64];
    char                    user_agent[128];

    /* Extranonce */
    uint8_t                 extranonce1[STRATUM_EXTRANONCE1_SIZE];
    char                    extranonce1_hex[STRATUM_EXTRANONCE1_SIZE * 2 + 1];
    uint32_t                extranonce2;

    /* Current job */
    char                    current_job_id[STRATUM_JOB_ID_SIZE + 1];

    /* Difficulty */
    double                  difficulty;
    double                  vardiff_shares;     /* Shares since last vardiff adjust */
    time_t                  vardiff_time;       /* Last vardiff check time */

    /* Statistics */
    uint64_t                shares_accepted;
    uint64_t                shares_rejected;
    uint64_t                blocks_found;
    double                  hashrate;           /* Estimated hashrate */

    /* Receive buffer */
    char                    recv_buffer[STRATUM_RECV_BUFFER_SIZE];
    size_t                  recv_len;

    /* Send buffer */
    char                    send_buffer[STRATUM_SEND_BUFFER_SIZE];
    size_t                  send_len;
    size_t                  send_offset;

    /* Client ID */
    uint32_t                id;

} stratum_client_t;

/*==============================================================================
 * STRATUM JOB
 *============================================================================*/

typedef struct stratum_job {
    char                    job_id[STRATUM_JOB_ID_SIZE + 1];
    uint32_t                height;
    uint8_t                 prevhash[32];       /* Previous block hash */
    uint8_t                 merkle_root[32];    /* Merkle root */
    uint32_t                version;
    uint32_t                nbits;
    uint32_t                ntime;
    bool                    clean_jobs;

    /* Block template */
    ftc_block_t*            block_template;

} stratum_job_t;

/*==============================================================================
 * STRATUM SERVER
 *============================================================================*/

/* Forward declaration */
struct ftc_node;

typedef struct ftc_stratum {
    /* Configuration */
    uint16_t                port;
    double                  default_difficulty;
    bool                    vardiff_enabled;

    /* Socket */
    stratum_socket_t        listen_socket;

    /* Clients */
    stratum_client_t*       clients[STRATUM_MAX_CLIENTS];
    int                     client_count;
    uint32_t                next_client_id;
    uint32_t                next_extranonce1;

    /* Current job */
    stratum_job_t           current_job;
    uint32_t                next_job_id;

    /* State */
    bool                    running;
    time_t                  start_time;
    time_t                  last_job_broadcast;

    /* Statistics */
    uint64_t                total_shares;
    uint64_t                total_blocks;
    uint64_t                total_clients_connected;
    double                  pool_hashrate;

    /* Node reference */
    struct ftc_node*        node;

    /* P2Pool for payout distribution */
    ftc_p2pool_t*           p2pool;

} ftc_stratum_t;

/*==============================================================================
 * PUBLIC API
 *============================================================================*/

/**
 * Create Stratum server
 */
ftc_stratum_t* ftc_stratum_new(struct ftc_node* node, uint16_t port);

/**
 * Free Stratum server
 */
void ftc_stratum_free(ftc_stratum_t* stratum);

/**
 * Start Stratum server
 */
bool ftc_stratum_start(ftc_stratum_t* stratum);

/**
 * Stop Stratum server
 */
void ftc_stratum_stop(ftc_stratum_t* stratum);

/**
 * Process events (non-blocking poll)
 */
void ftc_stratum_poll(ftc_stratum_t* stratum);

/**
 * Notify all clients of new job
 */
void ftc_stratum_notify_new_block(ftc_stratum_t* stratum);

/**
 * Get connected miner count
 */
int ftc_stratum_get_miner_count(ftc_stratum_t* stratum);

/**
 * Get pool hashrate estimate
 */
double ftc_stratum_get_hashrate(ftc_stratum_t* stratum);

/**
 * Get pool statistics
 */
typedef struct ftc_stratum_stats {
    uint64_t    total_shares;
    uint64_t    total_blocks;
    int         active_miners;
    double      pool_hashrate;
    time_t      uptime;
} ftc_stratum_stats_t;

void ftc_stratum_get_stats(ftc_stratum_t* stratum, ftc_stratum_stats_t* stats);

#ifdef __cplusplus
}
#endif

#endif /* FTC_STRATUM_H */
