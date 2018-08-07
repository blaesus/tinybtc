#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "parameters.h"
// @see https://en.bitcoin.it/wiki/Protocol_documentation#version
// @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

typedef uint8_t VariableLengthInteger[64];

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string

struct VariableLengthString {
    uint8_t string[9];
    VariableLengthInteger length;
};

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Network_address

struct NetworkAddress {
    uint32_t time;
    uint64_t services;
    uint8_t ip[16];
    uint16_t port;
};

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

union Payload {
    struct VersionPayload version;
};

typedef union Payload Payload;

struct Message {
    uint32_t magic;
    uint8_t command[12];
    uint32_t length;
    uint32_t checksum;
    Payload *payload;
};

int serialize_version_message(struct Message *message, uint8_t *data);
