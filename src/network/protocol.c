/**
 * FTC P2P Protocol Implementation
 *
 * Message serialization and building
 */

#include "protocol.h"
#include "../crypto/keccak256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*==============================================================================
 * COMMAND STRINGS
 *============================================================================*/

static const char* MSG_COMMANDS[] = {
    "",             /* 0 - unused */
    "version",      /* 1 */
    "verack",       /* 2 */
    "ping",         /* 3 */
    "pong",         /* 4 */
    "getaddr",      /* 5 */
    "addr",         /* 6 */
    "inv",          /* 7 */
    "getdata",      /* 8 */
    "notfound",     /* 9 */
    "block",        /* 10 */
    "tx",           /* 11 */
    "getblocks",    /* 12 */
    "getheaders",   /* 13 */
    "headers",      /* 14 */
    "mempool",      /* 15 */
    "reject",       /* 16 */
};

/*==============================================================================
 * MESSAGE CHECKSUM
 *============================================================================*/

uint32_t ftc_msg_checksum(const uint8_t* payload, size_t len)
{
    ftc_hash256_t hash;
    ftc_keccak256(payload, len, hash);
    return (uint32_t)hash[0] |
           ((uint32_t)hash[1] << 8) |
           ((uint32_t)hash[2] << 16) |
           ((uint32_t)hash[3] << 24);
}

/*==============================================================================
 * MESSAGE HEADER
 *============================================================================*/

void ftc_msg_header_serialize(const ftc_msg_header_t* header, uint8_t out[24])
{
    /* Magic (little-endian) */
    out[0] = (uint8_t)(header->magic);
    out[1] = (uint8_t)(header->magic >> 8);
    out[2] = (uint8_t)(header->magic >> 16);
    out[3] = (uint8_t)(header->magic >> 24);

    /* Command (12 bytes, zero-padded) */
    memcpy(out + 4, header->command, 12);

    /* Length (little-endian) */
    out[16] = (uint8_t)(header->length);
    out[17] = (uint8_t)(header->length >> 8);
    out[18] = (uint8_t)(header->length >> 16);
    out[19] = (uint8_t)(header->length >> 24);

    /* Checksum */
    out[20] = (uint8_t)(header->checksum);
    out[21] = (uint8_t)(header->checksum >> 8);
    out[22] = (uint8_t)(header->checksum >> 16);
    out[23] = (uint8_t)(header->checksum >> 24);
}

bool ftc_msg_header_deserialize(const uint8_t data[24], ftc_msg_header_t* header)
{
    header->magic = (uint32_t)data[0] |
                    ((uint32_t)data[1] << 8) |
                    ((uint32_t)data[2] << 16) |
                    ((uint32_t)data[3] << 24);

    memcpy(header->command, data + 4, 12);
    header->command[11] = '\0';  /* Ensure null-terminated */

    header->length = (uint32_t)data[16] |
                     ((uint32_t)data[17] << 8) |
                     ((uint32_t)data[18] << 16) |
                     ((uint32_t)data[19] << 24);

    header->checksum = (uint32_t)data[20] |
                       ((uint32_t)data[21] << 8) |
                       ((uint32_t)data[22] << 16) |
                       ((uint32_t)data[23] << 24);

    return header->magic == FTC_PROTOCOL_MAGIC;
}

/*==============================================================================
 * MESSAGE BUILDING
 *============================================================================*/

size_t ftc_msg_build(
    ftc_msg_type_t type,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out,
    size_t out_len)
{
    if (payload_len > FTC_MAX_MESSAGE_SIZE) return 0;
    if (out_len < 24 + payload_len) return 0;

    ftc_msg_header_t header;
    header.magic = FTC_PROTOCOL_MAGIC;
    memset(header.command, 0, 12);
    strncpy(header.command, ftc_msg_type_to_string(type), 11);
    header.length = (uint32_t)payload_len;
    header.checksum = payload_len > 0 ? ftc_msg_checksum(payload, payload_len) : 0;

    ftc_msg_header_serialize(&header, out);

    if (payload_len > 0 && payload) {
        memcpy(out + 24, payload, payload_len);
    }

    return 24 + payload_len;
}

/*==============================================================================
 * VERSION MESSAGE
 *============================================================================*/

size_t ftc_msg_version_build(
    const ftc_version_msg_t* version,
    uint8_t* out,
    size_t out_len)
{
    /* Calculate payload size */
    size_t user_agent_len = strlen(version->user_agent);
    size_t payload_len = 4 + 8 + 8 + 26 + 26 + 8 + 1 + user_agent_len + 4 + 1;

    if (out_len < 24 + payload_len) return 0;

    uint8_t payload[256];
    size_t pos = 0;

    /* Version (4 bytes) */
    payload[pos++] = (uint8_t)(version->version);
    payload[pos++] = (uint8_t)(version->version >> 8);
    payload[pos++] = (uint8_t)(version->version >> 16);
    payload[pos++] = (uint8_t)(version->version >> 24);

    /* Services (8 bytes) */
    for (int i = 0; i < 8; i++) {
        payload[pos++] = (uint8_t)(version->services >> (i * 8));
    }

    /* Timestamp (8 bytes) */
    for (int i = 0; i < 8; i++) {
        payload[pos++] = (uint8_t)(version->timestamp >> (i * 8));
    }

    /* Receiver address (26 bytes) */
    for (int i = 0; i < 8; i++) {
        payload[pos++] = (uint8_t)(version->addr_recv.services >> (i * 8));
    }
    memcpy(payload + pos, version->addr_recv.ip, 16);
    pos += 16;
    payload[pos++] = (uint8_t)(version->addr_recv.port >> 8);  /* Big-endian */
    payload[pos++] = (uint8_t)(version->addr_recv.port);

    /* Sender address (26 bytes) */
    for (int i = 0; i < 8; i++) {
        payload[pos++] = (uint8_t)(version->addr_from.services >> (i * 8));
    }
    memcpy(payload + pos, version->addr_from.ip, 16);
    pos += 16;
    payload[pos++] = (uint8_t)(version->addr_from.port >> 8);  /* Big-endian */
    payload[pos++] = (uint8_t)(version->addr_from.port);

    /* Nonce (8 bytes) */
    for (int i = 0; i < 8; i++) {
        payload[pos++] = (uint8_t)(version->nonce >> (i * 8));
    }

    /* User agent (varint length + string) */
    payload[pos++] = (uint8_t)user_agent_len;
    memcpy(payload + pos, version->user_agent, user_agent_len);
    pos += user_agent_len;

    /* Start height (4 bytes) */
    payload[pos++] = (uint8_t)(version->start_height);
    payload[pos++] = (uint8_t)(version->start_height >> 8);
    payload[pos++] = (uint8_t)(version->start_height >> 16);
    payload[pos++] = (uint8_t)(version->start_height >> 24);

    /* Relay (1 byte) */
    payload[pos++] = version->relay;

    return ftc_msg_build(FTC_MSG_VERSION, payload, pos, out, out_len);
}

/*==============================================================================
 * SIMPLE MESSAGES
 *============================================================================*/

size_t ftc_msg_verack_build(uint8_t* out, size_t out_len)
{
    return ftc_msg_build(FTC_MSG_VERACK, NULL, 0, out, out_len);
}

size_t ftc_msg_ping_build(uint64_t nonce, uint8_t* out, size_t out_len)
{
    uint8_t payload[8];
    for (int i = 0; i < 8; i++) {
        payload[i] = (uint8_t)(nonce >> (i * 8));
    }
    return ftc_msg_build(FTC_MSG_PING, payload, 8, out, out_len);
}

size_t ftc_msg_pong_build(uint64_t nonce, uint8_t* out, size_t out_len)
{
    uint8_t payload[8];
    for (int i = 0; i < 8; i++) {
        payload[i] = (uint8_t)(nonce >> (i * 8));
    }
    return ftc_msg_build(FTC_MSG_PONG, payload, 8, out, out_len);
}

size_t ftc_msg_getaddr_build(uint8_t* out, size_t out_len)
{
    return ftc_msg_build(FTC_MSG_GETADDR, NULL, 0, out, out_len);
}

/*==============================================================================
 * INVENTORY MESSAGES
 *============================================================================*/

size_t ftc_msg_inv_build(
    const ftc_inv_t* inv,
    size_t count,
    uint8_t* out,
    size_t out_len)
{
    if (count > FTC_MAX_INV_COUNT) return 0;

    /* Varint + (4 + 32) per inv */
    size_t payload_len = 9 + count * 36;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return 0;

    size_t pos = 0;

    /* Count (varint) */
    pos += ftc_varint_encode(count, payload + pos);

    /* Inventory vectors */
    for (size_t i = 0; i < count; i++) {
        payload[pos++] = (uint8_t)(inv[i].type);
        payload[pos++] = (uint8_t)(inv[i].type >> 8);
        payload[pos++] = (uint8_t)(inv[i].type >> 16);
        payload[pos++] = (uint8_t)(inv[i].type >> 24);
        memcpy(payload + pos, inv[i].hash, 32);
        pos += 32;
    }

    size_t result = ftc_msg_build(FTC_MSG_INV, payload, pos, out, out_len);
    free(payload);
    return result;
}

size_t ftc_msg_getdata_build(
    const ftc_inv_t* inv,
    size_t count,
    uint8_t* out,
    size_t out_len)
{
    if (count > FTC_MAX_INV_COUNT) return 0;

    size_t payload_len = 9 + count * 36;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return 0;

    size_t pos = 0;
    pos += ftc_varint_encode(count, payload + pos);

    for (size_t i = 0; i < count; i++) {
        payload[pos++] = (uint8_t)(inv[i].type);
        payload[pos++] = (uint8_t)(inv[i].type >> 8);
        payload[pos++] = (uint8_t)(inv[i].type >> 16);
        payload[pos++] = (uint8_t)(inv[i].type >> 24);
        memcpy(payload + pos, inv[i].hash, 32);
        pos += 32;
    }

    size_t result = ftc_msg_build(FTC_MSG_GETDATA, payload, pos, out, out_len);
    free(payload);
    return result;
}

/*==============================================================================
 * BLOCK/TX MESSAGES
 *============================================================================*/

size_t ftc_msg_block_build(
    const ftc_block_t* block,
    uint8_t* out,
    size_t out_len)
{
    /* Get serialized block size */
    size_t block_size = ftc_block_serialize(block, NULL, 0);
    if (block_size == 0) return 0;

    uint8_t* payload = (uint8_t*)malloc(block_size);
    if (!payload) return 0;

    if (ftc_block_serialize(block, payload, block_size) != block_size) {
        free(payload);
        return 0;
    }

    size_t result = ftc_msg_build(FTC_MSG_BLOCK, payload, block_size, out, out_len);
    free(payload);
    return result;
}

size_t ftc_msg_tx_build(
    const ftc_tx_t* tx,
    uint8_t* out,
    size_t out_len)
{
    size_t tx_size = ftc_tx_serialize(tx, NULL, 0);
    if (tx_size == 0) return 0;

    uint8_t* payload = (uint8_t*)malloc(tx_size);
    if (!payload) return 0;

    if (ftc_tx_serialize(tx, payload, tx_size) != tx_size) {
        free(payload);
        return 0;
    }

    size_t result = ftc_msg_build(FTC_MSG_TX, payload, tx_size, out, out_len);
    free(payload);
    return result;
}

/*==============================================================================
 * HEADERS MESSAGES
 *============================================================================*/

size_t ftc_msg_getheaders_build(
    const ftc_hash256_t* locator,
    size_t locator_count,
    const ftc_hash256_t stop_hash,
    uint8_t* out,
    size_t out_len)
{
    /* 4 + varint + locator_count * 32 + 32 */
    size_t payload_len = 4 + 9 + locator_count * 32 + 32;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return 0;

    size_t pos = 0;

    /* Protocol version */
    payload[pos++] = FTC_PROTOCOL_VERSION & 0xff;
    payload[pos++] = (FTC_PROTOCOL_VERSION >> 8) & 0xff;
    payload[pos++] = (FTC_PROTOCOL_VERSION >> 16) & 0xff;
    payload[pos++] = (FTC_PROTOCOL_VERSION >> 24) & 0xff;

    /* Locator count */
    pos += ftc_varint_encode(locator_count, payload + pos);

    /* Locator hashes */
    for (size_t i = 0; i < locator_count; i++) {
        memcpy(payload + pos, locator[i], 32);
        pos += 32;
    }

    /* Stop hash */
    memcpy(payload + pos, stop_hash, 32);
    pos += 32;

    size_t result = ftc_msg_build(FTC_MSG_GETHEADERS, payload, pos, out, out_len);
    free(payload);
    return result;
}

size_t ftc_msg_headers_build(
    const ftc_block_header_t* headers,
    size_t count,
    uint8_t* out,
    size_t out_len)
{
    if (count > FTC_MAX_HEADERS_COUNT) return 0;

    /* varint + count * (80 header + 1 tx_count) */
    size_t payload_len = 9 + count * 81;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return 0;

    size_t pos = 0;
    pos += ftc_varint_encode(count, payload + pos);

    for (size_t i = 0; i < count; i++) {
        ftc_block_header_serialize(&headers[i], payload + pos);
        pos += 80;
        payload[pos++] = 0;  /* tx_count = 0 for headers */
    }

    size_t result = ftc_msg_build(FTC_MSG_HEADERS, payload, pos, out, out_len);
    free(payload);
    return result;
}

/*==============================================================================
 * ADDR MESSAGE
 *============================================================================*/

size_t ftc_msg_addr_build(
    const ftc_net_addr_t* addrs,
    size_t count,
    uint8_t* out,
    size_t out_len)
{
    if (count > FTC_MAX_ADDR_COUNT) return 0;

    /* varint + count * (4 timestamp + 8 services + 16 ip + 2 port) */
    size_t payload_len = 9 + count * 30;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return 0;

    size_t pos = 0;
    pos += ftc_varint_encode(count, payload + pos);

    for (size_t i = 0; i < count; i++) {
        /* Timestamp (4 bytes, current time) */
        uint32_t now = (uint32_t)time(NULL);
        payload[pos++] = (uint8_t)(now);
        payload[pos++] = (uint8_t)(now >> 8);
        payload[pos++] = (uint8_t)(now >> 16);
        payload[pos++] = (uint8_t)(now >> 24);

        /* Services (8 bytes) */
        for (int j = 0; j < 8; j++) {
            payload[pos++] = (uint8_t)(addrs[i].services >> (j * 8));
        }

        /* IP (16 bytes) */
        memcpy(payload + pos, addrs[i].ip, 16);
        pos += 16;

        /* Port (2 bytes, big-endian) */
        payload[pos++] = (uint8_t)(addrs[i].port >> 8);
        payload[pos++] = (uint8_t)(addrs[i].port);
    }

    size_t result = ftc_msg_build(FTC_MSG_ADDR, payload, pos, out, out_len);
    free(payload);
    return result;
}

/*==============================================================================
 * TYPE HELPERS
 *============================================================================*/

const char* ftc_msg_type_to_string(ftc_msg_type_t type)
{
    if (type >= 1 && type <= 16) {
        return MSG_COMMANDS[type];
    }
    return "unknown";
}

ftc_msg_type_t ftc_msg_string_to_type(const char* command)
{
    for (int i = 1; i <= 16; i++) {
        if (strncmp(command, MSG_COMMANDS[i], 12) == 0) {
            return (ftc_msg_type_t)i;
        }
    }
    return (ftc_msg_type_t)0;
}
