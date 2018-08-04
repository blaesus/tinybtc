#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "inet.h"

void cleanup() {
    printf("Cleaning up\n");
    close_tcp_connections();
}

int main() {
    setup_listen_socket();
    dns_bootstrap();
    establish_tcp_connections();
    monitor_incoming_messages();
    atexit(&cleanup);
    return 0;
}
