#include <stdio.h>
#include <unistd.h>

#include "Block.h"
#include "message.h"
#include "parameters.h"
#include "globalstate.h"
#include "inet.h"

int inspect_global_state() {
    puts("Global state inspection");
    for (int i = 0; i < globalState.peerCount; i++) {
        if (globalState.peers[i].active) {
            char *ipString = convert_ipv4_readable(globalState.peers[i].ip);
            printf("%s, ", ipString);
        }
    }
    return 0;
}

int find_more_addr() {
    const uint32_t initialIpCount = globalState.peerCount;
    for (int peerIndex = 0; peerIndex < globalState.peerCount; peerIndex++) {
        globalState.peers[peerIndex];
    }
    return 0;
}


int main() {
    dns_bootstrap();
    establish_tcp_connections();
    inspect_global_state();
    close_tcp_connections();
    return 0;
}
