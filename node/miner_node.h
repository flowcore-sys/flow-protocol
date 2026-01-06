/**
 * FTC Standalone Miner - Header
 */

#ifndef FTC_MINER_NODE_H
#define FTC_MINER_NODE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * MINER STATISTICS
 *============================================================================*/

typedef struct {
    uint64_t total_hashes;      /* Total hashes computed */
    uint64_t blocks_found;      /* Blocks found (valid PoW) */
    uint64_t blocks_accepted;   /* Blocks accepted by node */
    uint64_t blocks_rejected;   /* Blocks rejected by node */
    uint32_t current_nonce;     /* Current nonce being tested */
} miner_stats_t;

#ifdef __cplusplus
}
#endif

#endif /* FTC_MINER_NODE_H */
