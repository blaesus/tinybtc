#include <string.h>
#include <stdbool.h>
#include "globalstate.h"

GlobalState globalState = {
    .peers = {},
    .peerCount = 0,
};

void add_peer(IP ip) {
    const uint32_t index = globalState.peerCount;
    globalState.peerCount += 1;

    memset(&globalState.peers[index], 0, sizeof(struct Peer));

    globalState.peers[index].active = 1;
    memcpy(globalState.peers[index].ip, ip, sizeof(IP));
}
