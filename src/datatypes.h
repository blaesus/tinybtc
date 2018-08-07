#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "uv.h"

#define BITS_IN_BYTE 8 // TODO: Dubious?

#define DOMAIN_NAME_LENGTH 50

#define MAX_VARIABLE_LENGTH_STRING_LENGTH 256 // Technically it could be larger

typedef uint8_t IP[16];

typedef char DomainName[DOMAIN_NAME_LENGTH];

typedef uint64_t ServiceBits;

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

typedef uint8_t VariableLengthInteger[64];

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string

struct VariableLengthString {
    uint8_t string[MAX_VARIABLE_LENGTH_STRING_LENGTH];
    uint64_t length;
};

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
struct NetworkAddress {
    uint64_t services;
    IP ip;
    uint16_t port;
};

struct NetworkAddressWithTime {
    // version >= 31402
    uint32_t time;
    uint64_t services;
    uint8_t ip[16];
    uint16_t port;
};

struct Peer {
    bool valid;
    uv_tcp_t *socket;
    bool myClient;
    struct NetworkAddress address;
};
