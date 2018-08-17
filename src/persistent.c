#include <stdio.h>

#include "persistent.h"

#include "globalstate.h"
#include "networking.h"
#include "util.h"

#define PEER_LIST_FILENAME "peers.dat"

int32_t save_peer_addresses_human() {
    FILE *file = fopen("peers.csv", "wb");

    for (uint64_t i = 0; i < global.peerAddressCount; i++) {
        struct AddressRecord *record = &global.peerAddresses[i];
        char *ipString = convert_ipv4_readable(record->ip);
        fprintf(file, "%s\n", ipString);
    }
    fclose(file);

    return 0;
}

int32_t save_peer_addresses() {
    dedupe_global_addr_cache();
    FILE *file = fopen(PEER_LIST_FILENAME, "wb");

    uint8_t peerCountBytes[4] = { 0 };
    segment_int32(global.peerAddressCount, peerCountBytes);
    fwrite(peerCountBytes, 1, sizeof(global.peerAddressCount), file);

    fwrite(
        &global.peerAddresses,
        global.peerAddressCount,
        sizeof(struct AddressRecord),
        file
    );

    printf("Saved %u peers\n", global.peerAddressCount);

    fclose(file);

    save_peer_addresses_human();
    return 0;
}

int32_t load_peer_addresses() {
    printf("Loading global state ");
    FILE *file = fopen(PEER_LIST_FILENAME, "rb");

    Byte buffer[sizeof(struct AddressRecord)] = {0};

    fread(&buffer, 1, 4, file);
    global.peerAddressCount = combine_uint32(buffer);
    printf("(%u peers to recover)...", global.peerAddressCount);
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        fread(&buffer, 1, sizeof(struct AddressRecord), file);
        memcpy(&global.peerAddresses[index], buffer, sizeof(struct AddressRecord));
    }
    printf("Done.\n");
    return 0;
}


int32_t init_db() {
    printf("Connecting to redis database...\n");
    redisContext *c;
    const char *hostname = "127.0.0.1";
    int port = 6379;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c = redisConnectWithTimeout(hostname, port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        return 1;
    }
    printf("Redis connected\n");
    return 0;
}

