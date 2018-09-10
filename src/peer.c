#include "stdlib.h"
#include "peer.h"

void reset_peer(Peer *ptrPeer) {
    if (ptrPeer->socket.data) {
        free(ptrPeer->socket.data);
    }
    memset(ptrPeer, 0, sizeof(*ptrPeer));
}
