#include <string.h>
#include <stdbool.h>
#include "globalstate.h"

GlobalState globalState = {
    .peers = {},
    .peerCount = 0,
};

void add_peer(IP ip) {
    globalState.peerCount += 1;
    globalState.peers[globalState.peerCount].active = 1;
    memcpy(globalState.peers[globalState.peerCount].ip, ip, sizeof(IP));
}
