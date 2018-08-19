#include <stdio.h>
#include "redis/hiredis.h"

#include "persistent.h"

#include "globalstate.h"
#include "networking.h"
#include "util.h"

#define PEER_LIST_BINARY_FILENAME "peers.dat"
#define PEER_LIST_CSV_FILENAME "peers.csv"

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
    clear_old_addr();
    FILE *file = fopen(PEER_LIST_BINARY_FILENAME, "wb");

    uint8_t peerCountBytes[PEER_ADDRESS_COUNT_WIDTH] = { 0 };
    segment_int32(global.peerAddressCount, peerCountBytes);
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

