#include <string.h>
#include <stdbool.h>
#include "globalstate.h"

GlobalState global;

void add_peer_address(IP ip) {
    const uint32_t index = global.peerAddressCount;
    global.peerAddressCount += 1;
    memcpy(global.peerAddresses[index], ip, sizeof(IP));
}
