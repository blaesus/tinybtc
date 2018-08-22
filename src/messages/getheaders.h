#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "messages/shared.h"
#include "hash.h"

#define MAX_HASH_PER_GETHEADERS 2000

struct GetheadersPayload {
    int32_t version;
    VarIntMem hashCount;
    SHA256_HASH blockLocatorHash[MAX_HASH_PER_GETHEADERS];
    SHA256_HASH hashStop;
};

typedef struct GetheadersPayload GetheadersPayload;

uint64_t serialize_getheaders_payload(
    GetheadersPayload *ptrPayload,
    Byte *ptrBuffer
);

int32_t make_getheaders_message(
    Message *ptrMessage,
    GetheadersPayload *ptrPayload
);

uint64_t serialize_getheader_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);

uint64_t load_getheaders_message(
    char *path,
    Message *ptrMessage
);
