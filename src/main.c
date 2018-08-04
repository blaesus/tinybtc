#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "inet.h"
#include "data.h"
#include "globalstate.h"

void cleanup() {
    printf("Cleaning up\n");
    close_tcp_connections();
    saveGlobalState();
}

int main() {
    loadGlobalState();
    setup_listen_socket();
    if (!globalState.peerCount) {
        dns_bootstrap();
    }
//    establish_tcp_connections();
//    monitor_incoming_messages();
    atexit(&cleanup);
    return 0;
}
