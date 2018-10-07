#include <stdlib.h>

#include "communication.h"
#include "persistent.h"
#include "globalstate.h"
#include "blockchain.h"
#include "config.h"
#include "utils/networking.h"
#include "utils/opt.h"

#include "test/test.h"


int32_t run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

void setup_cleanup() {
    atexit(&terminate_execution);
    struct sigaction sa = {
        .sa_handler = &terminate_execution,
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
}

int8_t init(int32_t argc, char **argv) {
    printf("Initializing...\n");
    handle_options(argc, argv);
    global.start_time = time(NULL);
    srand((unsigned int)global.start_time);
    setup_cleanup();
    init_block_index_map();
    load_peer_candidates();
    if (global.peerCandidateCount == 0) {
        dns_bootstrap();
    }
    int8_t dbError = init_db();
    if (dbError) {
        return -1;
    }
    init_archive_dir();
    load_genesis();
    load_block_indices();
    scan_block_indices(false, false);
    if (global.mode == MODE_NORMAL && should_catchup()) {
        global.mode = MODE_CATCHUP;
        printf("Activated catchup mode\n");
    }
    printf("Done initialization.\n");
    return 0;
}

int32_t connect_to_peers() {
    // connect_to_local();
    connect_to_initial_peers();
    return 0;
}

int32_t main(int32_t argc, char **argv) {
    int8_t initError = init(argc, argv);
    if (initError) {
        fprintf(stderr, "init error %i\n", initError);
        return -1;
    }
    switch (global.mode) {
        case MODE_VALIDATE: {
            uint32_t *time = global.modeData;
            revalidate(*time);
            return 0;
        }
        case MODE_VALIDATE_ONE: {
            Byte *hash = global.modeData;
            validate_block(hash, false, NULL);
            return 0;
        }
        case MODE_TEST: {
            test();
            return 0;
        }
        default: {
            setup_main_event_loop();
            connect_to_peers();
            run_main_loop();
        }
    }
    return 0;
}
