#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "parameters.h"
#include "datatypes.h"

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
    int32_t start_height;

    // After version 70001
    bool relay;
};

typedef struct VersionPayload VersionPayload;

union Payload {
    struct VersionPayload version;
};

typedef union Payload Payload;

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure

#define CHECKSUM_SIZE 4
typedef uint8_t PayloadChecksum[CHECKSUM_SIZE];

#define MESSAGE_HEADER_FIELDS \
    uint32_t magic; \
    uint8_t command[12]; \
    uint32_t length; \
    PayloadChecksum checksum; \

struct MessageHeader {
    MESSAGE_HEADER_FIELDS
};

typedef struct MessageHeader MessageHeader;

struct Message {
    MESSAGE_HEADER_FIELDS
    Payload *payload;
};

typedef struct Message Message;

uint64_t serialize_version_message(
        struct Message *ptrMessage,
        uint8_t *ptrBuffer,
        uint32_t bufferSize
);
uint64_t serialize_verack_message(
        struct Message *ptrMessage,
        uint8_t *ptrBuffer,
        uint32_t bufferSize
);
void make_verack_message(Message *ptrMessage);
uint8_t serialize_to_varint(uint64_t data, uint8_t *ptrBuffer);
uint8_t parse_varint(
        uint8_t *ptrBuffer,
        uint64_t *result
);
uint64_t serialize_varstr(
        struct VariableLengthString *ptrVarStr,
        uint8_t *ptrBuffer
);
uint64_t serializeVersionPayload(
        struct VersionPayload *ptrPayload,
        uint8_t *ptrBuffer,
        uint32_t bufferSize
);
uint32_t make_version_payload_to_peer(
        struct Peer *ptrPeer,
        struct VersionPayload *ptrPayload
);
void make_version_message(
        struct Message *ptrMessage,
        struct VersionPayload *ptrPayload,
        uint32_t payloadLength
);

uint64_t parse_message_header(
        uint8_t *buffer,
        struct Message *ptrMessage
);

uint64_t parse_version_payload(
        uint8_t *ptrBuffer,
        struct VersionPayload *ptrPayload
);

bool begins_width_header(void *p);
