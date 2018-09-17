#include <stdio.h>
#include <stdlib.h>
#include "leveldb/c.h"

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
    printf("Connecting to LevelDB...");
    leveldb_t *db;
    leveldb_options_t *options = leveldb_options_create();
    leveldb_options_set_create_if_missing(options, 1);
    char *error = NULL;
    db = leveldb_open(options, config.dbName, &error);
    if (error != NULL) {
        fprintf(stderr, "Open LevelDB fail: %s\n", error);
        return -1;
    }
    leveldb_free(error);
    leveldb_free(options);
    global.db = db;
    printf("Done.\n");
    return 0;
}

static bool file_exist(char *filename) {
    struct stat buffer;
    return stat(filename, &buffer) == 0;
}

int32_t save_block_indices(void) {
    FILE *file = fopen(BLOCK_INDICES_FILENAME, "wb");
    fwrite(&global.mainTip, sizeof(global.mainTip), 1, file);

    Byte *keys = CALLOC(MAX_BLOCK_COUNT, SHA256_LENGTH, "save_block_indices:keys");
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
    FREE(keys, "save_block_indices:keys");
    fclose(file);
    return 0;
}

int32_t load_block_indices(void) {
    if (!file_exist(BLOCK_INDICES_FILENAME)) {
        fprintf(stderr, "block index file does not exist; skipping import\n");
        return -1;
    }
    FILE *file = fopen(BLOCK_INDICES_FILENAME, "rb");
    fread(&global.mainTip, sizeof(global.mainTip), 1, file);
    uint32_t headersCount = 0;
    fread(&headersCount, sizeof(headersCount), 1, file);
    for (uint32_t i = 0; i < headersCount; i++) {
        BlockIndex index;
        memset(&index, 0, sizeof(index));
        fread(&index, sizeof(index), 1, file);
        hashmap_set(&global.blockIndices, index.meta.hash, &index, sizeof(index));
    }
    printf("Loaded %u headers\n", headersCount);
    return 0;
}

int8_t save_data_by_hash(Byte *hash, Byte *value, uint64_t valueLength) {
    uint32_t keyLength = SHA256_HEXSTR_LENGTH;
    char key[SHA256_HEXSTR_LENGTH] = {0};
    hash_binary_to_hex(hash, key);
    char *error = NULL;
    leveldb_writeoptions_t *writeOptions = leveldb_writeoptions_create();
    leveldb_put(
        global.db, writeOptions,
        key, keyLength,
        (char*)value, valueLength,
        &error
    );

    if (error != NULL) {
        fprintf(stderr, "Write fail: %s\n", error);
        return -1;
    }
    leveldb_free(error);
    leveldb_free(writeOptions);
    return 0;
}

int8_t load_data_by_hash(Byte *hash, Byte *output) {
    const uint32_t keyLength = SHA256_HEXSTR_LENGTH;
    char key[SHA256_HEXSTR_LENGTH] = {0};
    hash_binary_to_hex(hash, key);

    size_t read_len;
    char *error;
    leveldb_readoptions_t *readOptions = leveldb_readoptions_create();
    char *read = leveldb_get(
        global.db, readOptions,
        key, keyLength,
        &read_len,
        &error
    );

    if (error != NULL) {
        fprintf(stderr, "Read fail: %s\n", error);
        print_object(error, 5);
        return -1;
    }
    leveldb_free(error);
    leveldb_free(readOptions);
    memcpy(output, read, read_len);
    return 0;
}

bool check_existence_by_hash(Byte *hash) {
    uint32_t keyLength = SHA256_HEXSTR_LENGTH;
    char key[SHA256_HEXSTR_LENGTH] = {0};
    hash_binary_to_hex(hash, key);

    size_t read_len;
    char *error;
    leveldb_readoptions_t *readOptions = leveldb_readoptions_create();
    leveldb_get(
        global.db, readOptions,
        (char*)key, keyLength,
        &read_len,
        &error
    );

    if (error != NULL) {
        return false;
    }
    leveldb_free(error);
    leveldb_free(readOptions);
    return read_len > 0;
}

int8_t save_block(BlockPayload *ptrBlock) {
    SHA256_HASH hash = {0};
    hash_block_header(&ptrBlock->header, hash);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_block:buffer");
    uint64_t width = serialize_block_payload(ptrBlock, buffer);
    save_data_by_hash(hash, buffer, width);
    FREE(buffer, "save_block:buffer");
    return 0;
}

int8_t load_block(Byte *hash, BlockPayload *ptrBlock) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_block:buffer");
    load_data_by_hash(hash, buffer);
    parse_into_block_payload(buffer, ptrBlock);
    FREE(buffer, "load_block:buffer");
    return 0;
}

int8_t save_tx(TxPayload *ptrTx) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_tx:buffer");
    uint64_t width = serialize_tx_payload(ptrTx, buffer);
    SHA256_HASH hash = {0};
    dsha256(buffer, (uint32_t)width, hash);
    save_data_by_hash(hash, buffer, width);
    FREE(buffer, "save_tx:buffer");
    return 0;
}

int8_t load_tx(Byte *hash, TxPayload *ptrPayload) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_tx:buffer");

    load_data_by_hash(hash, buffer);
    parse_into_tx_payload(buffer, ptrPayload);
    FREE(buffer, "load_tx:buffer");
    return 0;
}

bool check_block_existence(Byte *hash) {
    return check_existence_by_hash(hash);
}


void save_chain_data() {
    printf("Saving chain data...\n");
    save_peer_addresses();
    save_block_indices();
    printf("Done.");
}

void load_genesis() {
    printf("Loading genesis block...\n");
    Message genesis = get_empty_message();
    load_block_message("genesis.dat", &genesis);
    BlockPayload *ptrBlock = (BlockPayload*) genesis.ptrPayload;
    memcpy(&global.genesisBlock, ptrBlock, sizeof(BlockPayload));
    hash_block_header(&ptrBlock->header, global.genesisHash);
    process_incoming_block(ptrBlock);
    printf("Done.\n");
}

