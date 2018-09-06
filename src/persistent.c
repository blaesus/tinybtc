#include <stdio.h>
#include <stdlib.h>
#include "hiredis/hiredis.h"

#include "persistent.h"

#include "globalstate.h"
#include "networking.h"
#include "blockchain.h"
#include "util.h"
#include "config.h"

#define PEER_LIST_BINARY_FILENAME "peers.dat"
#define PEER_LIST_CSV_FILENAME "peers.csv"

#define BLOCK_INDICES_FILENAME "block_indices.dat"

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


int8_t init_db() {
    printf("Connecting to redis database...");

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    global.ptrRedisContext = redisConnectWithTimeout(config.redisHost, config.redisPort, timeout);
    if (global.ptrRedisContext == NULL || global.ptrRedisContext->err) {
        if (global.ptrRedisContext ) {
            printf("\nConnection error: %s\n", global.ptrRedisContext->errstr);
        } else {
            printf("\nConnection error: can't allocate redis context\n");
        }
        return 1;
    }
    printf("Done.\n");
    return 0;
}

int32_t save_headers(void) {
    FILE *file = fopen(BLOCK_INDICES_FILENAME, "wb");
    Byte *keys = calloc(1000000, SHA256_LENGTH);
    uint32_t keyCount = (uint32_t)hashmap_getkeys(&global.blockIndices, keys);
    printf("Saving %u block indices to %s...\n", keyCount, BLOCK_INDICES_FILENAME);
    fwrite(&keyCount, sizeof(keyCount), 1, file);
    uint32_t actualCount = 0;
    for (uint32_t i = 0; i < keyCount; i++) {
        Byte key[SHA256_LENGTH] = {0};
        memcpy(key, keys + i * SHA256_LENGTH, SHA256_LENGTH);
        BlockIndex *ptrIndex = hashmap_get(&global.blockIndices, key, NULL);
        if (ptrIndex) {
            fwrite(ptrIndex, sizeof(BlockIndex), 1, file);
            actualCount += 1;
        }
        else {
            printf("Key not found\n");
        }
    }
    printf("Exported %u block indices \n", actualCount);
    free(keys);
    fclose(file);
    return 0;
}

int32_t load_headers(void) {
    FILE *file = fopen(BLOCK_INDICES_FILENAME, "rb");
    uint32_t headersCount = 0;
    fread(&headersCount, sizeof(headersCount), 1, file);
    for (uint32_t i = 0; i < headersCount; i++) {
        BlockIndex index;
        memset(&index, 0, sizeof(index));
        fread(&index, sizeof(index), 1, file);
        hashmap_set(&global.blockIndices, index.hash, &index, sizeof(index));
        hashmap_set(&global.blockPrevBlockToHash, index.header.prev_block, index.hash, sizeof(index.hash));
    }
    printf("Loaded %u headers\n", headersCount);
    return 0;
}

int8_t save_block(BlockPayload *ptrBlock, Byte *hash) {
    Byte *buffer = calloc(1, MESSAGE_BUFFER_LENGTH);
    uint64_t width = serialize_block_payload(ptrBlock, buffer);
    redisReply *reply = redisCommand(
        global.ptrRedisContext,
        "SET %b %b",
        hash, SHA256_LENGTH,
        buffer, width
    );
    if (reply == NULL) {
        return -1;
    }
    else if (reply->type == REDIS_REPLY_ERROR) {
        printf("Save error: %s", reply->str);
        return -2;
    }
    freeReplyObject(reply);
    free(buffer);
    return 0;
}

int8_t load_block(Byte *hash, BlockPayload *ptrBlock) {
    Byte *buffer = calloc(1, MESSAGE_BUFFER_LENGTH);
    redisReply *reply = redisCommand(
        global.ptrRedisContext,
        "GET %b",
        hash, SHA256_LENGTH
    );
    if (reply == NULL) {
        printf("Load error: null reply");
        return -1;
    }
    else if (reply->type == REDIS_REPLY_ERROR) {
        printf("Load error: %s", reply->str);
        return -2;
    }
    memcpy(buffer, reply->str, reply->len);
    parse_into_block_payload(buffer, ptrBlock);
    freeReplyObject(reply);
    free(buffer);
    return 0;
}

bool check_block_existence(Byte *hash) {
    redisReply *reply = redisCommand(
        global.ptrRedisContext,
        "EXISTS %b",
        hash, SHA256_LENGTH
    );
    if (reply == NULL) {
        printf("Redis error: null reply");
        return 0;
    }
    else if (reply->type == REDIS_REPLY_ERROR) {
        printf("Redis error: %s", reply->str);
        return 0;
    }
    int64_t result = reply->integer;
    freeReplyObject(reply);
    return (bool)result;
}
