#include <stdlib.h>

#include "uv/uv.h"

#include "communication.h"
#include "networking.h"
#include "persistent.h"
#include "globalstate.h"
#include "blockchain.h"

#include "test/test.h"

void cleanup() {
    printf("\nCleaning up\n");
    uv_loop_close(uv_default_loop());
    release_sockets();
    save_peer_addresses();
    save_headers();
    redisFree(global.ptrRedisContext);
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

void load_genesis() {
    printf("Loading genesis block...");
    SHA256_HASH genesisHash = {0};
    Message genesis = get_empty_message();
    load_block_message("genesis.dat", &genesis);
    BlockPayload *ptrBlock = (BlockPayload*) genesis.ptrPayload;

    dsha256(&ptrBlock->header, sizeof(ptrBlock->header), genesisHash);
    BlockIndex index = {
        .fullBlockAvailable = true,
        .hash = {0},
        .header = ptrBlock->header
    };
    memcpy(index.hash, genesisHash, SHA256_LENGTH);
    hashmap_set(&global.blockIndices, genesisHash, &index, sizeof(index));
    save_block(ptrBlock, genesisHash);

    global.mainChainTarget = ptrBlock->header.target;

    memcpy(&global.genesisBlock, ptrBlock, sizeof(BlockPayload));
    memcpy(global.genesisHash, genesisHash, SHA256_LENGTH);
    global.mainChainHeight = mainnet.genesisHeight;
    memcpy(global.mainChainTip, genesisHash, SHA256_LENGTH);
    printf("Done.\n");
}

int8_t init() {
    printf("Initializing...\n");
    printf("Size of global state: %lu\n", sizeof(global.blockIndices));
    global.start_time = time(NULL);
    srand((unsigned int)global.start_time);
    setup_cleanup();
    hashmap_init(&global.blockIndices, (1UL << 25) - 1, SHA256_LENGTH);
    hashmap_init(&global.blockPrevBlockToHash, (1UL << 25) - 1, SHA256_LENGTH);
    int8_t dbError = init_db();
    if (dbError) {
        return -1;
    }
    load_genesis();
    load_headers();
    relocate_main_chain();
    load_peer_addresses();
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
    }
    setup_main_event_loop();
    printf("Done initialization.\n");
    return 0;
}

int32_t connect_to_peers() {
    // setup_listen_socket();
    // connect_to_local();
    connect_to_initial_peers();
    return 0;
}

int32_t main(/* int32_t argc, char **argv */) {
    int8_t initError = init();
    if (initError) {
        fprintf(stderr, "init error %i\n", initError);
        return -1;
    }
    connect_to_peers();
    run_main_loop();

    // test();
    return 0;
}

