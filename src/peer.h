#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "uv/uv.h"
#include "datatypes.h"

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
    uint32_t chain_height;
};

typedef struct Peer Peer;

void reset_peer(Peer *ptrPeer);
