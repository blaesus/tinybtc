#include <stdlib.h>

#include "uv/uv.h"

#include "communication.h"
#include "networking.h"
#include "persistent.h"
#include "globalstate.h"

#include "test/test.h"

void cleanup() {
    printf("\nCleaning up\n");
    uv_loop_close(uv_default_loop());
    release_sockets();
    save_peer_addresses();
    printf("\nGood byte!\n");
}

int32_t run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

void setup_cleanup() {
    atexit(&cleanup);
    struct sigaction sa = {
        .sa_handler = &cleanup,
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
}

void init() {
    global.start_time = time(NULL);
    srand((unsigned int)global.start_time);
    setup_cleanup();
    load_peer_addresses();
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
    }
    setup_main_event_loop();
    init_db();
}

int32_t connect_to_peers() {
    // setup_listen_socket();
    // connect_to_local();
    connect_to_initial_peers();
    return 0;
}

int32_t main(/* int32_t argc, char **argv */) {
    // init();
    // connect_to_peers();
    // run_main_loop();

    test();
    return 0;
}

