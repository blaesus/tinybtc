#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "hash.h"
#include "messages/tx.h"

#define TARGET_BITS_MANTISSA_WIDTH 3
#define TARGET_BITS_EXPONENT_WIDTH 1
#define TARGET_BITS_WIDTH (TARGET_BITS_MANTISSA_WIDTH + TARGET_BITS_EXPONENT_WIDTH)

typedef uint32_t TargetCompact;

struct BlockPayloadHeader {
    int32_t version;
    SHA256_HASH prev_block;
    SHA256_HASH merkle_root;
    uint32_t timestamp;
    TargetCompact target;
    uint32_t nonce;
};

typedef struct BlockPayloadHeader BlockPayloadHeader;

struct BlockPayload {
    BlockPayloadHeader header;
    VarIntMem txCount;
    TxNode *ptrFirstTxNode;
};

typedef struct BlockPayload BlockPayload;

uint64_t serialize_block_payload(BlockPayload *ptrPayload, Byte *ptrBuffer);
int32_t make_block_message(Message *ptrMessage, BlockPayload *ptrPayload);
uint64_t serialize_block_message(Message *ptrMessage, uint8_t *ptrBuffer);
uint64_t parse_block_payload_header(Byte *ptrBuffer, BlockPayloadHeader *ptrHeader);
uint64_t serialize_block_payload_header(BlockPayloadHeader *ptrHeader, Byte *ptrBuffer);
int32_t parse_into_block_payload(Byte *ptrBuffer, BlockPayload *ptrBlock);
uint64_t load_block_message(char *path, Message *ptrMessage);
void print_block_message(Message *ptrMessage);
int32_t parse_into_block_message(Byte *ptrBuffer, Message *ptrMessage);
bool is_block_legal(BlockPayload *ptrBlock);
bool is_block_header_legal(BlockPayloadHeader *ptrHeader);
bool hash_satisfies_target_compact(const Byte *hash, TargetCompact target);
void target_4to32(TargetCompact targetBytes, Byte *bytes);
void hash_block_header(BlockPayloadHeader *ptrHeader, Byte *hash);
void print_block_payload(BlockPayload *ptrBlock);
void release_tx_in_block(BlockPayload *ptrBlock);
bool is_block(Message *ptrMessage);
