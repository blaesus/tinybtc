#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "hash.h"
#include "messages/tx.h"

#define MAX_TX_PER_BLOCK 4096

struct BlockPayload {
    int32_t version;
    SHA256_HASH prev_block;
    SHA256_HASH merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    uint64_t txn_count;
    TX txns[MAX_TX_PER_BLOCK];
};

typedef struct BlockPayload BlockPayload;

