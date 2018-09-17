#include "stdlib.h"
#include "peer.h"
#include "util.h"

void reset_peer(Peer *ptrPeer) {
    if (ptrPeer->socket.data) {
        FREE(ptrPeer->socket.data, "SocketContext");
    }
    memset(ptrPeer, 0, sizeof(*ptrPeer));
}
