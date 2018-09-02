#pragma once
#include <stdint.h>
#include "bn.h"
#include "hash.h"
#include "datatypes.h"
#include "messages/block.h"

struct BlockIndex {
    BlockPayloadHeader header;
    SHA256_HASH hash;
    bool fullBlockAvailable;
};

typedef struct BlockIndex BlockIndex;

void target_4to32(TargetCompact targetBytes, Byte *bytes);
long double targetQuodToRoughDouble(TargetCompact targetBytes);
void targetCompactToBignum(TargetCompact targetBytes, BIGNUM *ptrTarget);
uint32_t targetBignumToCompact(BIGNUM *ptrTarget);

bool hash_satisfies_target(const Byte *hash, const Byte *target);
bool validate_blockchain(BlockPayloadHeader ptrFirstHeader, uint32_t chainLength);
void relocate_main_chain(void);
bool is_block_header_legal_as_tip(BlockPayloadHeader *ptrHeader);
void target_mul(Byte *targetBytes, long double ratio, Byte *result);

