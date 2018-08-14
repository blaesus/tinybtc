#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "globalstate.h"
#include "data.h"
#include "inet.h"

#define PEER_LIST_FILENAME "peers.dat"

int save_peer_addresses() {
    FILE *file = fopen(PEER_LIST_FILENAME, "wb");

    uint8_t peerCountBytes[4] = { 0 };
    segment_int32(global.peerAddressCount, peerCountBytes);
    fwrite(peerCountBytes, 1, 4, file);

    for (uint8_t index = 0; index < global.peerAddressCount; index++) {
        fwrite(global.peerAddresses[index], 1, 16, file);
    }

    printf("Saved %u peers\n", global.peerAddressCount);

    fclose(file);
    return 0;
}

int load_peer_addresses() {
    printf("Loading global state ");
    FILE *file = fopen(PEER_LIST_FILENAME, "rb");

    uint8_t buffer[16] = {0};

    fread(&buffer, 1, 4, file);
    global.peerAddressCount = combine_uint32(buffer);
    printf("(%u peers to recover)...", global.peerAddressCount);
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        fread(&buffer, 1, 16, file);
        memcpy(global.peerAddresses[index], buffer, sizeof(IP));
    }
    printf("Done\n");
    return 0;
}
