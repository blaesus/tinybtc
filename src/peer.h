#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "libuv/include/uv.h"
#include "datatypes.h"
#include "hash.h"

struct HandshakeState {
    bool acceptThem : 1;
    bool acceptUs : 1;
};

struct PingState {
    double pingSent;
    double pongReceived;
    uint64_t nonce;
};

struct RequestsState {
    SHA256_HASH block;
    struct PingState ping;
};

#define REL_MY_SERVER 0
#define REL_MY_CLIENT 1

struct Peer {
    uint32_t index;
    struct HandshakeState handshake;
    struct RequestsState requests;

    uv_tcp_t socket;
    double connectionStart;

    uint8_t relationship;
    NetworkAddress address;
    uint32_t chain_height;
};

typedef struct Peer Peer;

void reset_peer(Peer *ptrPeer);
