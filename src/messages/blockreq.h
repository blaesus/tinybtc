#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "messages/shared.h"
#include "hash.h"

#define MAX_LOCATORS_PER_BLOCK_REQUEST 2000

struct BlockRequestPayload {
    int32_t version;
    VarIntMem hashCount;
    SHA256_HASH blockLocatorHash[MAX_LOCATORS_PER_BLOCK_REQUEST];
    SHA256_HASH hashStop;
};

typedef struct BlockRequestPayload BlockRequestPayload;

uint64_t serialize_blockreq_payload(
    BlockRequestPayload *ptrPayload,
    Byte *ptrBuffer
);

int32_t make_blockreq_message(
    Message *ptrMessage,
    BlockRequestPayload *ptrPayload,
    char *command,
    uint8_t commandSize
);

uint64_t serialize_blockreq_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);

uint64_t load_blockreq_message(
    char *path,
    Message *ptrMessage
);
