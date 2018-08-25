#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "hash.h"
#include "messages/tx.h"

struct BlockPayloadHeader {
    int32_t version;
    SHA256_HASH prev_block;
    SHA256_HASH merkle_root;
    uint32_t timestamp;
    uint32_t target_bits;
    uint32_t nonce;
};

typedef struct BlockPayloadHeader BlockPayloadHeader;

struct BlockPayload {
    BlockPayloadHeader header;
    VarIntMem txCount;
    TxNode *ptrFirstTxNode;
};

typedef struct BlockPayload BlockPayload;

uint64_t serialize_block_payload(
    BlockPayload *ptrPayload,
    Byte *ptrBuffer
);

int32_t make_block_message(
    Message *ptrMessage,
    BlockPayload *ptrPayload
);

uint64_t serialize_block_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);

uint64_t parse_block_payload_header(
    Byte *ptrBuffer,
    BlockPayloadHeader *ptrHeader
);

uint64_t serialize_block_payload_header(
    BlockPayloadHeader *ptrHeader,
    Byte *ptrBuffer
);

int32_t parse_into_block_payload(
    Byte *ptrBuffer,
    BlockPayload *ptrBlock
);

uint64_t load_block_message(
    char *path,
    Message *ptrMessage
);
