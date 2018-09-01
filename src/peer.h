#pragma once

#include <stdbool.h>
#include "datatypes.h"
#include "parameters.h"

struct MessageCache {
    uint64_t bufferIndex;
    Byte buffer[MESSAGE_BUFFER_LENGTH];
    uint64_t expectedMessageLength;
};

typedef struct MessageCache MessageCache;

struct HandshakeState {
    bool acceptThem : 1;
    bool acceptUs : 1;
};

#define REL_MY_SERVER 0
#define REL_MY_CLIENT 1

struct Peer {
    uint32_t index;
    struct HandshakeState handshake;

    uv_tcp_t socket;
    time_t connectionStart;

    uint8_t relationship;
    NetworkAddress address;
    MessageCache messageCache;
    uint32_t chain_height;
};

typedef struct Peer Peer;

void reset_peer(Peer *ptrPeer);
