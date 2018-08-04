#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "globalstate.h"
#include "data.h"
#include "inet.h"
#include <arpa/inet.h>

#define PEER_LIST_FILENAME "peers.dat"

int segment_int32(uint32_t number, char chars[4]) {
    chars[0] = (uint8_t)(number & 0xFF);
    chars[1] = (uint8_t)((number >> 1 * BYTE) & 0xFF);
    chars[2] = (uint8_t)((number >> 2 * BYTE) & 0xFF);
    chars[3] = (uint8_t)((number >> 3 * BYTE) & 0xFF);
    return 0;
}

uint32_t combine_int32(uint8_t chars[4]) {
    uint32_t number = (chars[3] << 3 * BYTE)
                      + (chars[2] << 2 * BYTE)
                      + (chars[1] << 1 * BYTE)
                      + (chars[0]);
    return number;
}

int saveGlobalState() {
    FILE *file = fopen(PEER_LIST_FILENAME, "wb");

    char peerCountBytes[4] = { 0 };
    segment_int32(globalState.peerCount, peerCountBytes);
    fwrite(peerCountBytes, 1, 4, file);

    for (uint8_t index = 0; index < globalState.peerCount; index++) {
        fwrite(globalState.peers[index].ip, 1, 16, file);
    }

    fclose(file);
    return 0;
};

int loadGlobalState() {
    puts("Loading global state");
    FILE *file = fopen(PEER_LIST_FILENAME, "rb");

    uint8_t buffer[16] = {0};

    fread(&buffer, 1, 4, file);
    globalState.peerCount = combine_int32(buffer);
    printf("%u peers to recover\n", globalState.peerCount);
    for (int index = 0; index < globalState.peerCount; index++) {
        fread(&buffer, 1, 16, file);
        memset(&globalState.peers[index], 0, sizeof(struct Peer));
        memcpy(globalState.peers[index].ip, buffer, sizeof(IP));
        globalState.peers[index].active = true;
        printf("recovered peer %s\n", convert_ipv4_readable(globalState.peers[index].ip));
    }
    return 0;
}
