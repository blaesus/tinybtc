#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "Block.h"
#include "message.h"
#include "parameters.h"
#include "globalstate.h"
#include "inet.h"

void cleanup() {
    printf("Cleaning up\n");
    close_tcp_connections();
}

int main() {
    int error;
    error = setup_listen_socket();
    if (error) {
        printf("Cannot setup listen socket");
        return -1;
    }
    monitor_incoming_messages();
//    dns_bootstrap();
    add_loopback_peer();
//    establish_tcp_connections();
    atexit(&cleanup);
    return 0;
}
