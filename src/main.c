#include <stdlib.h>

#include "leveldb/c.h"
#include "libuv/include/uv.h"

#include "communication.h"
#include "networking.h"
#include "persistent.h"
#include "globalstate.h"
#include "blockchain.h"
#include "config.h"

#include "test/test.h"

void cleanup() {
    printf("\nCleaning up\n");
    uv_loop_close(uv_default_loop());
    save_chain_data();
    leveldb_close(global.db);
    release_sockets();
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
    sigaction(SIGKILL, &sa, NULL);
}

int8_t init() {
    printf("Initializing...\n");
    printf("Size of global state: %lu\n", sizeof(global.blockIndices));
    global.start_time = time(NULL);
    srand((unsigned int)global.start_time);
    setup_cleanup();
    hashmap_init(&global.blockIndices, (1UL << 25) - 1, SHA256_LENGTH);
    load_peer_candidates();
    if (global.peerCandidateCount == 0) {
        dns_bootstrap();
    }
    int8_t dbError = init_db();
    if (dbError) {
        return -1;
    }
    load_genesis();
    load_block_indices();
    double blockAvailability = verify_block_indices(config.verifyBlocks);
    if (blockAvailability < config.ibdModeAvailabilityThreshold) {
        global.ibdMode = true;
        printf("Activated IBD mode\n");
    }
    setup_main_event_loop();
    printf("Done initialization.\n");
    return 0;
}

int32_t connect_to_peers() {
    // connect_to_local();
    connect_to_initial_peers();
    return 0;
}

int32_t main(/* int32_t argc, char **argv */) {
    // test(); return 0;
    // migrate(); return 0;
    int8_t initError = init();
    if (initError) {
        fprintf(stderr, "init error %i\n", initError);
        return -1;
    }
    connect_to_peers();
    run_main_loop();

    return 0;
}

