#include <stdio.h>
#include <stdlib.h>
#include "hiredis/hiredis.h"

#include "persistent.h"

#include "globalstate.h"
#include "networking.h"
#include "util.h"

#define PEER_LIST_BINARY_FILENAME "peers.dat"
#define PEER_LIST_CSV_FILENAME "peers.csv"

#define BLOCK_HEADER_LIST_FILENAME "headers.dat"

int32_t save_peer_addresses_human() {
    FILE *file = fopen(PEER_LIST_CSV_FILENAME, "wb");

    for (uint64_t i = 0; i < global.peerAddressCount; i++) {
        struct AddrRecord *record = &global.peerAddresses[i];
        char *ipString = convert_ipv4_readable(record->net_addr.ip);
        fprintf(
            file,
            "%u,%s,%u,%llu\n",
            record->timestamp,
            ipString,
            ntohs(record->net_addr.port),
            record->net_addr.services
        );
    }
    fclose(file);

    return 0;
}

int32_t save_peer_addresses() {
    dedupe_global_addr_cache();
    if (global.peerAddressCount > CLEAR_OLD_ADDR_THRESHOLD) {
        clear_old_addr();
    }
    FILE *file = fopen(PEER_LIST_BINARY_FILENAME, "wb");

    uint8_t peerCountBytes[PEER_ADDRESS_COUNT_WIDTH] = { 0 };
    segment_uint32(global.peerAddressCount, peerCountBytes);
    fwrite(peerCountBytes, sizeof(global.peerAddressCount), 1, file);

    fwrite(
        &global.peerAddresses,
        global.peerAddressCount,
        sizeof(struct AddrRecord),
        file
    );

    printf("Saved %u peers\n", global.peerAddressCount);

    fclose(file);

    save_peer_addresses_human();
    return 0;
}

int32_t load_peer_addresses() {
    printf("Loading global state ");
    FILE *file = fopen(PEER_LIST_BINARY_FILENAME, "rb");

    Byte buffer[sizeof(struct AddrRecord)] = {0};

    fread(&buffer, PEER_ADDRESS_COUNT_WIDTH, 1, file);
    global.peerAddressCount = combine_uint32(buffer);
    printf("(%u peers to recover)...", global.peerAddressCount);
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        fread(&buffer, 1, sizeof(struct AddrRecord), file);
        memcpy(&global.peerAddresses[index], buffer, sizeof(struct AddrRecord));
    }
    printf("Done.\n");
    return 0;
}


int32_t init_db() {
    printf("Connecting to redis database...");
    redisContext *c;
    const char *hostname = "127.0.0.1";
    int port = 6379;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c = redisConnectWithTimeout(hostname, port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            printf("\nConnection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("\nConnection error: can't allocate redis context\n");
        }
        return 1;
    }
    printf("Done\n");
    return 0;
}

int32_t save_headers(void) {
    FILE *file = fopen(BLOCK_HEADER_LIST_FILENAME, "wb");
    Byte *keys = calloc(1000000, SHA256_LENGTH);
    uint32_t keyCount = (uint32_t)hashmap_getkeys(&global.headers, keys);
    printf("Saving %u headers to %s...\n", keyCount, BLOCK_HEADER_LIST_FILENAME);
    fwrite(&keyCount, sizeof(keyCount), 1, file);
    uint32_t actualCount = 0;
    for (uint32_t i = 0; i < keyCount; i++) {
        Byte key[SHA256_LENGTH] = {0};
        memcpy(key, keys + i * SHA256_LENGTH, SHA256_LENGTH);
        BlockPayloadHeader *ptrData = hashmap_get(&global.headers, key, NULL);
        if (ptrData) {
            fwrite(ptrData, sizeof(BlockPayloadHeader), 1, file);
            actualCount += 1;
        }
        else {
            printf("Key not found\n");
        }
    }
    printf("keyCount = %u, Actual export = %u\n", keyCount, actualCount);
    free(keys);
    fclose(file);
    return 0;
}

int32_t load_headers(void) {
    FILE *file = fopen(BLOCK_HEADER_LIST_FILENAME, "rb");
    uint32_t headersCount = 0;
    fread(&headersCount, sizeof(headersCount), 1, file);
    for (uint32_t i = 0; i < headersCount; i++) {
        BlockPayloadHeader header;
        memset(&header, 0, sizeof(header));
        fread(&header, sizeof(header), 1, file);

        SHA256_HASH headerHash = {0};
        dsha256(&header, sizeof(header), headerHash);
        hashmap_set(&global.headers, headerHash, &header, sizeof(header));
        hashmap_set(&global.headersPrevBlockToHash, header.prev_block, headerHash, sizeof(headerHash));
    }
    printf("Loaded %u headers\n", headersCount);
    return 0;
}
