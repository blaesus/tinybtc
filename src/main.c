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

    // Save in headers hashmap
    dsha256(&ptrBlock->header, sizeof(ptrBlock->header), genesisHash);
    hashmap_set(&global.headers, genesisHash, &ptrBlock->header, sizeof(BlockPayloadHeader));
    global.mainChainTarget = ptrBlock->header.target;

    // Save in global
    memcpy(&global.genesisBlock, ptrBlock, sizeof(BlockPayload));
    global.mainChainHeight = parameters.genesisHeight;
    memcpy(global.mainChainTip, genesisHash, SHA256_LENGTH);
    printf("Done.\n");
}

void init() {
    printf("Initializing...\n");
    global.start_time = time(NULL);
    srand((unsigned int)global.start_time);
    setup_cleanup();
    hashmap_init(&global.headers, (1UL << 25) - 1, SHA256_LENGTH);
    hashmap_init(&global.headersByPrevBlock, (1UL << 25) - 1, SHA256_LENGTH);
    load_genesis();
    load_headers();
    relocate_main_chain();
    load_peer_addresses();
    init_db();
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
    }
    setup_main_event_loop();
    printf("Done initialization.\n");
}

int32_t connect_to_peers() {
    // setup_listen_socket();
    // connect_to_local();
    connect_to_initial_peers();
    return 0;
}

void find() {
    SHA256_HASH targetHash = {
        0xcc,0xd6,0x64,0x6e,0x5f,0xf7,0x3a,0xe9,0x70,0x1a,0xa5,0xc3,0x57,0x5b,0x1a,0xbf,0x66,0xf6,0x2d,0xd3,0x98,0xc9,0x37,0x5b,0x07,0x4c,0x07,0xde,0x00,0x00,0x00,0x00
    };
    BlockPayloadHeader *ptrHeader = hashmap_get(&global.headers, targetHash, NULL);
    if (ptrHeader) {
        printf("Found!");
    }
    else {
        printf("NOT Found!");
    }
}

int32_t main(/* int32_t argc, char **argv */) {
    init();
    // connect_to_peers();
    // run_main_loop();

    // test();
    return 0;
}

