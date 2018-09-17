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

enum PeerRelationship {
    PEER_RELATIONSHIP_OUR_SERVER = 0x01,
    PEER_RELATIONSHIP_OUR_CLIENT = 0x02,
};

struct Peer {
    uint32_t index;
    struct HandshakeState handshake;
    struct RequestsState requests;

    uv_tcp_t socket;
    double connectionStart;

    enum PeerRelationship relationship;
    NetworkAddress address;
    uint32_t chain_height;
};

typedef struct Peer Peer;

void reset_peer(Peer *ptrPeer);
