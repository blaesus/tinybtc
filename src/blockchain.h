#pragma once
#include <stdint.h>
#include "hash.h"
#include "datatypes.h"
#include "messages/block.h"

void expand_target(uint32_t targetBits, SHA256_HASH hash);
int8_t hashcmp(
    const Byte *hashA,
    const Byte *hashB,
    uint32_t width
);
bool hash_satisfies_target(
    const Byte *hash,
    const Byte *target
);
bool validate_blockchain(
    BlockPayloadHeader ptrFirstHeader,
    uint32_t chainLength
);
void relocate_main_chain(void);
