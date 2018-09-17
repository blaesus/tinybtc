#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "libuv/include/uv.h"
#include "datatypes.h"
#include "hash.h"

#define PEER_LATENCY_SLOT 5

struct HandshakeState {
    bool acceptThem : 1;
    bool acceptUs : 1;
};

struct PingState {
    double pingSent;
    double pongReceived;
    uint64_t nonce;
};

struct InteractionState {
    SHA256_HASH requesting;
    struct PingState ping;
    double lastHeard;
    double latencies[PEER_LATENCY_SLOT];
    uint32_t lattencyIndex;
};

enum PeerRelationship {
    PEER_RELATIONSHIP_OUR_SERVER = 0x01,
    PEER_RELATIONSHIP_OUR_CLIENT = 0x02,
};

struct Peer {
    uint32_t index;
    struct HandshakeState handshake;
    struct InteractionState networking;

    uv_tcp_t socket;
    double connectionStart;

    enum PeerRelationship relationship;
    NetworkAddress address;
    uint32_t chain_height;
};

typedef struct Peer Peer;

void reset_peer(Peer *ptrPeer);
double average_peer_latency(Peer *ptrPeer);
