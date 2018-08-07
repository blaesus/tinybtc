#include <string.h>
#include <stdbool.h>
#include "globalstate.h"

GlobalState global = {
    .listenSocket = {0},
    .peers = {},
    .peerCount = 0,
    .eventCounter = 0,
    .blockchainHeight = 0,
};

void add_peer(IP ip, bool myClient) {
    const uint32_t index = global.peerCount;
    global.peerCount += 1;

    memset(&global.peers[index], 0, sizeof(struct Peer));

    global.peers[index].valid = 1;
    global.peers[index].myClient = myClient;
    memcpy(global.peers[index].address.ip, ip, sizeof(IP));
}
