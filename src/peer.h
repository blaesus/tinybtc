#pragma once

#include <stdbool.h>
#include "datatypes.h"
#include "parameters.h"

struct MessageCache {
    uint64_t bufferIndex;
    Byte buffer[65536];
    uint64_t expectedLength;
};

typedef struct MessageCache MessageCache;

struct HandshakeState {
    uint8_t acceptThem : 1;
    uint8_t acceptUs : 1;
};

struct PeerFlags {
    bool attemptedGetaddr;
};

#define REL_MY_SERVER 0
#define REL_MY_CLIENT 1

struct Peer {
    uint32_t index;
    struct HandshakeState handshake;
    uv_tcp_t *socket;
    uv_connect_t *connection;
    uint8_t relationship;
    NetworkAddress address;
    MessageCache messageCache;
    struct PeerFlags flags;
};

typedef struct Peer Peer;

