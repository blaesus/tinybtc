#include <stdlib.h>

#include "uv/uv.h"

#include "communication.h"
#include "networking.h"
#include "persistent.h"
#include "globalstate.h"

#include "test/test.h"

void cleanup() {
    printf("Cleaning up\n");
    free_networking_resources();
    save_peer_addresses();
    printf("\nGood byte!\n");
}

int32_t run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

void init() {
    load_peer_addresses();
    srand((unsigned int)time(NULL));
    setup_main_event_loop(true);
    init_db();
}

int32_t setup_peers() {
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
    }
    setup_listen_socket();
    connect_to_initial_peers();
    return 0;
}

int32_t main(/* int32_t argc, char **argv */) {
    // init();
    // setup_peers();
    // run_main_loop();
    // atexit(&cleanup);
    test();
    return 0;
}

