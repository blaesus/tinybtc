#pragma once
#include <stdint.h>
#include "openssl/bn.h"
#include "hash.h"
#include "datatypes.h"
#include "messages/block.h"

#define MAX_BLOCK_COUNT 1000000

#define MAX_CHILDREN_PER_BLOCK 16

#define CHAIN_STATUS_MAINCHAIN 0
#define CHAIN_STATUS_SIDECHAIN 1
#define CHAIN_STATUS_ORPHAN    2

#define HEADER_EXISTED 100

struct BlockChildren {
    SHA256_HASH hashes[MAX_CHILDREN_PER_BLOCK];
    uint16_t length;
};

struct BlockMeta {
    SHA256_HASH hash;
    bool fullBlockAvailable;
    bool fullBlockValidated;
    bool outputsRegistered;
};

struct BlockContext {
    uint8_t chainStatus;
    uint32_t height;
    double chainPOW;
    struct BlockChildren children;
};

struct BlockIndex {
    BlockPayloadHeader header;
    struct BlockMeta meta;
    struct BlockContext context;
};

typedef struct BlockIndex BlockIndex;

double target_compact_to_float(TargetCompact targetBytes);
void target_compact_to_bignum(TargetCompact targetBytes, BIGNUM *ptrTarget);
uint32_t target_bignum_to_compact(BIGNUM *ptrTarget);

double calc_block_pow(TargetCompact targetFloat);
int8_t process_incoming_block_header(BlockPayloadHeader *ptrHeader);
int8_t process_incoming_block(BlockPayload *ptrBlock);
double verify_block_indices(bool loadBlock);
bool is_block_valid(BlockPayload *ptrCandidate, BlockIndex *ptrIndex);
uint32_t max_full_block_height_from_genesis(void);
uint32_t validate_blocks(bool fromGenesis, uint32_t maxBlocksToCheck);
void revalidate(uint32_t totalBlocksToCheck);
