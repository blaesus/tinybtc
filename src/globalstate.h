#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "parameters.h"
#include "datatypes.h"
#include "peer.h"
#include "hashmap.h"
#include "messages/block.h"
#include "blockchain.h"

#define MAX_PEERS 256
#define MAX_PEER_CANDIDATES 32768
#define PEER_ADDRESS_COUNT_WIDTH 4
#define MAX_ORPHAN_COUNT 4096

#define MAX_ZOMBIE_SOCKETS 1024

struct GlobalState {
    bool ibdMode;
    void *timerTable;

    uv_tcp_t apiSocket;
    void *db;

    PeerCandidate peerCandidates[MAX_PEER_CANDIDATES];
    uint32_t peerCandidateCount;

    Peer peers[MAX_PEERS];
    uint32_t peerCount;

    time_t start_time;
    NetworkAddress myAddress;

    Hashmap blockIndices;
    SHA256_HASH orphans[MAX_ORPHAN_COUNT];
    uint16_t orphanCount;

    BlockPayload genesisBlock;
    SHA256_HASH genesisHash;

    void *zombieSockets[MAX_ZOMBIE_SOCKETS];
    uint32_t zombineSocketCount;

    BlockIndex mainTip;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_address_as_candidate(NetworkAddress netAddr, uint32_t timestamp);

void filter_peer_candidates();

bool is_peer(PeerCandidate *ptrCandidate);
uint32_t find_missing_blocks(SHA256_HASH *hashes, uint32_t desiredCount);
bool is_block_being_requested(Byte *hash);
uint32_t count_hand_shaken_peers();
bool peer_hand_shaken(Peer *ptrPeer);
