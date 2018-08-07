#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "globalstate.h"
#include "data.h"
#include "inet.h"

#define PEER_LIST_FILENAME "peers.dat"

int save_peers() {
    FILE *file = fopen(PEER_LIST_FILENAME, "wb");

    uint8_t peerCountBytes[4] = { 0 };
    segment_int32(global.peerCount, peerCountBytes);
    fwrite(peerCountBytes, 1, 4, file);

    for (uint8_t index = 0; index < global.peerCount; index++) {
        fwrite(global.peers[index].address.ip, 1, 16, file);
    }

    fclose(file);
    return 0;
};

int load_peers() {
    printf("Loading global state ");
    FILE *file = fopen(PEER_LIST_FILENAME, "rb");

    uint8_t buffer[16] = {0};

    fread(&buffer, 1, 4, file);
    global.peerCount = combine_uint32(buffer);
    printf("(%u peers to recover)...", global.peerCount);
    for (uint32_t index = 0; index < global.peerCount; index++) {
        fread(&buffer, 1, 16, file);
        memset(&global.peers[index], 0, sizeof(struct Peer));
        memcpy(global.peers[index].address.ip, buffer, sizeof(IP));
        global.peers[index].valid = true;
    }
    printf("Done\n");
    return 0;
}
