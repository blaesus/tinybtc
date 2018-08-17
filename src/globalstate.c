#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "globalstate.h"

GlobalState global;

void add_peer_address(IP ip, uint32_t timestamp) {
    const uint32_t index = global.peerAddressCount;
    global.peerAddressCount += 1;
    global.peerAddresses[index].timestamp = timestamp;
    memcpy(global.peerAddresses[index].ip, ip, sizeof(IP));
}
