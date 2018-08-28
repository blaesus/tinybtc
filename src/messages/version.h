#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "shared.h"
#include "peer.h"

// @see https://en.bitcoin.it/wiki/Protocol_documentation#version

struct VersionPayload {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
    struct NetworkAddress addr_recv;

    // After version 106
    struct NetworkAddress addr_from;
    uint64_t nonce;
    struct VariableLengthString user_agent;
    uint32_t start_height;

    // After version 70001
    bool relay;
};

typedef struct VersionPayload VersionPayload;

uint64_t serialize_version_message(
    struct Message *ptrMessage,
    uint8_t *ptrBuffer
);

int32_t make_version_message(
    struct Message *ptrMessage,
    Peer *ptrPeer
);

int32_t parse_into_version_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_version_message(struct Message *ptrMessage);
