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

    BlockIndex mainTip;
    uint32_t maxFullBlockHeight;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_address_as_candidate(NetworkAddress netAddr, uint32_t timestamp);

void filter_peer_candidates();

bool set_candidate_timestamp(PeerCandidate *ptrCandidate, uint32_t timestamp);
bool set_candidate_services(PeerCandidate *ptrCandidate, ServiceBits bits);
bool set_candidate_lantecy(PeerCandidate *ptrCandidate, double averageLatency);
bool disable_candidate(PeerCandidate *ptrCandidate);

bool is_peer(PeerCandidate *ptrCandidate);
int8_t get_next_missing_block(Byte *hash);
bool is_block_being_requested(Byte *hash);
uint32_t get_handshaken_peer_count();
bool peer_hand_shaken(Peer *ptrPeer);
