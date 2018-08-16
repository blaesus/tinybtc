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

struct Peer {
    struct HandshakeState handshake;
    uv_tcp_t *socket;
    uv_connect_t *connection;
    bool myClient;
    struct NetworkAddress address;
    struct MessageCache messageCache;
};

typedef struct Peer Peer;

