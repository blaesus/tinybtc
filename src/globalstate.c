#include <string.h>
#include <stdbool.h>

#include "globalstate.h"
#include "util.h"
#include "networking.h"
#include "config.h"
#include "persistent.h"
#include "blockchain.h"

GlobalState global;

void add_address_as_candidate(NetworkAddress netAddr, uint32_t timestamp) {
    PeerCandidate candidate;
    memset(&candidate, 0, sizeof(candidate));
    memcpy(&candidate.addr.net_addr, &netAddr, sizeof(NetworkAddress));
    candidate.addr.timestamp = timestamp;
    candidate.averageLatency = 0;
    memcpy(
        &global.peerCandidates[global.peerCandidateCount],
        &candidate,
        sizeof(candidate)
    );
    global.peerCandidateCount += 1;
}

void filter_peer_candidates() {
    printf("Removing invalid address cache...\n");
    PeerCandidate *buffer = CALLOC(MAX_PEER_CANDIDATES, sizeof(PeerCandidate), "filter_peer_candidates:buffer");

    uint32_t newLength = 0;
    for (uint32_t index = 0; index < global.peerCandidateCount; index++) {
        PeerCandidate *candidate = &global.peerCandidates[index];

        bool duplicated = false;
        Byte *ipAtIndex = candidate->addr.net_addr.ip;
        for (uint32_t search = index+1; search < global.peerCandidateCount; search++) {
            Byte *ipAtSearch = global.peerCandidates[search].addr.net_addr.ip;
            if (ips_equal(ipAtSearch, ipAtIndex)) {
                duplicated = true;
                break;
            }
        }

        bool disabled = candidate->status == PEER_CANDIDATE_STATUS_DISABLED;

        bool shouldDrop = duplicated || disabled;

        if (!shouldDrop) {
            memcpy(&buffer[newLength++], candidate, sizeof(*candidate));
        }
    }
    printf("Removed invalid candidates: %u => %u\n", global.peerCandidateCount, newLength);

    memcpy(&global.peerCandidates, &buffer, sizeof(buffer));
    global.peerCandidateCount = newLength;

    FREE(buffer, "filter_peer_candidates:buffer");
}

bool is_peer(PeerCandidate *ptrCandidate) {
    for (uint32_t i = 0; i < global.peerCount; i++) {
        if (ips_equal(global.peers[i].address.ip, ptrCandidate->addr.net_addr.ip)) {
            return true;
        }
    }
    return false;
}

int8_t get_next_missing_block(Byte *hash) {
    SHA256_HASH finderHash = {0};
    memcpy(finderHash, global.genesisHash, SHA256_LENGTH);
    do {
        BlockIndex *index = hashmap_get(&global.blockIndices, finderHash, NULL);
        if (index == NULL) {
            return -1;
        }
        else if (!index->meta.fullBlockAvailable && !is_block_being_requested(finderHash)) {
            memcpy(hash, finderHash, SHA256_LENGTH);
            return 0;
        }
        else if (index->context.children.length == 0) {
            // Obtained all blocks
            return 1;
        }
        else {
            // TODO: Handle side chains
            memcpy(finderHash, index->context.children.hashes[0], SHA256_LENGTH);
        }
    } while (true);
}

bool is_block_being_requested(Byte *hash) {
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Byte *requesting = global.peers[i].networking.requesting;
        if (memcmp(requesting, hash, SHA256_LENGTH) == 0) {
            return true;
        }
    }
    return false;
}

bool peer_hand_shaken(Peer *ptrPeer) {
    return ptrPeer->handshake.acceptUs && ptrPeer->handshake.acceptThem;
}

uint32_t get_handshaken_peer_count() {
    uint32_t count = 0;
    for (uint32_t i = 0; i < global.peerCount; i++) {
        if (peer_hand_shaken(&global.peers[i])) {
            count++;
        }
    }
    return count;
}
