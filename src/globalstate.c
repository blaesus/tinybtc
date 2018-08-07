#include <string.h>
#include <stdbool.h>
#include "globalstate.h"

GlobalState global = {
    .listenSocket = -1,
    .peers = {},
    .peerCount = 0,
    .eventCounter = 0,
};

void add_peer(IP ip) {
    const uint32_t index = global.peerCount;
    global.peerCount += 1;

    memset(&global.peers[index], 0, sizeof(struct Peer));

    global.peers[index].valid = 1;
    memcpy(global.peers[index].ip, ip, sizeof(IP));
}
