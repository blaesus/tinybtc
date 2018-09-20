#include "stdlib.h"
#include "peer.h"
#include "util.h"

bool is_latency_fully_tested(Peer *ptrPeer) {
    for (uint32_t i = 0; i < PEER_LATENCY_SLOT; i++) {
        double latency = ptrPeer->networking.latencies[i];
        if (latency == 0) {
            return false;
        }
    }
    return true;
}

double average_peer_latency(Peer *ptrPeer) {
    double total = 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < PEER_LATENCY_SLOT; i++) {
        double latency = ptrPeer->networking.latencies[i];
        if (latency > 0) {
            total += latency;
            count += 1;
        }
    }
    if (count == 0) {
        return 0;
    }
    else {
        return total / (count * 1.0);
    }
}

void record_latency(Peer *ptrPeer, double latency) {
    ptrPeer->networking.latencies[ptrPeer->networking.lattencyIndex] = latency;
    ptrPeer->networking.lattencyIndex = (ptrPeer->networking.lattencyIndex + 1) % PEER_LATENCY_SLOT;
}
