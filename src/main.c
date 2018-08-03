#include <stdio.h>

#include "Block.h"
#include "parameters.h"
#include "globalstate.h"
#include "inet.h"

int checkGlobalState() {
    for (int i = 0; i < sizeof(globalState.peerIps) / sizeof(IP); i++) {
        if (!isIPEmpty(globalState.peerIps[i])) {
            char *ipString = convert_ipv4_readable(globalState.peerIps[i]);
            printf("%s\n", ipString);
        }
    }
    return 0;
}

int main() {
    dns_bootstrap();
    checkGlobalState();
    return 0;
}
