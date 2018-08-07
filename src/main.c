#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "uv.h"

#include "inet.h"
#include "comm.h"
#include "data.h"
#include "globalstate.h"

void cleanup() {
    printf("Cleaning up\n");
    free_networking_resources();
    save_peers();
}

int run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

int main() {
    load_peers();
    if (!global.peerCount) {
        dns_bootstrap();
    }
    setup_main_event_loop(false);
    setup_listen_socket();
    setup_peer_connections();
    run_main_loop();
    atexit(&cleanup);
    return 0;
}
