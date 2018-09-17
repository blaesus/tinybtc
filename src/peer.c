#include "stdlib.h"
#include "peer.h"
#include "util.h"

void reset_peer(Peer *ptrPeer) {
    if (ptrPeer->socket.data) {
        FREE(ptrPeer->socket.data, "SocketContext");
    }
    memset(ptrPeer, 0, sizeof(*ptrPeer));
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
