#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "libuv/include/uv.h"
#include "datatypes.h"
#include "hash.h"

#define PEER_LATENCY_SLOT 3

enum PeerCandidateStatus {
    PEER_CANDIDATE_STATUS_NORMAL,
    PEER_CANDIDATE_STATUS_DISABLED,
};

struct PeerCandidate {
    AddrRecord addr;
    double averageLatency;
    enum PeerCandidateStatus status;
};

typedef struct PeerCandidate PeerCandidate;

struct HandshakeState {
    bool acceptThem : 1;
    bool acceptUs : 1;
    double handshakeStart;
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
    uint64_t incomingBytes;
};

enum PeerRelationship {
    PEER_RELATIONSHIP_OUR_SERVER = 0x01,
    PEER_RELATIONSHIP_OUR_CLIENT = 0x02,
};

struct Peer {
    uint32_t slot;
    struct HandshakeState handshake;
    struct InteractionState networking;

    uv_tcp_t socket;
    double connectionStart;

    enum PeerRelationship relationship;
    NetworkAddress address;
    uint32_t chain_height;

    PeerCandidate *candidacy;
};

typedef struct Peer Peer;

typedef struct PeerCandidate PeerCandidate;

void reset_peer(Peer *ptrPeer);
double average_peer_latency(Peer *ptrPeer);
bool is_latency_fully_tested(Peer *ptrPeer);
void record_latency(Peer *ptrPeer, double latency);
