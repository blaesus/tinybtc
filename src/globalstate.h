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

#define GET_BLOCK_INDEX(hash) (hashmap_get(&global.blockIndices, hash, NULL))
#define SET_BLOCK_INDEX(hash, index) (hashmap_set(&global.blockIndices, hash, &index, sizeof(index)))

#define MAX_TIMERS 32

enum ExecutionMode {
    MODE_NORMAL = 0,
    MODE_CATCHUP,
    MODE_VALIDATE,
    MODE_TEST,
};

struct GlobalState {
    enum ExecutionMode mode;
    void *modeData;

    void *timerTable;

    uv_tcp_t apiSocket;
    void *txLocationDB;
    void *utxoDB;

    PeerCandidate peerCandidates[MAX_PEER_CANDIDATES];
    uint32_t peerCandidateCount;

    Peer *peers[MAX_PEERS];
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

    BlockIndex mainHeaderTip;
    BlockIndex mainValidatedTip;

    uv_timer_t *timers[MAX_TIMERS];
    uint32_t timerCount;
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
void add_orphan(Byte *hash);
void mark_block_as_unavailable(Byte *hash);
