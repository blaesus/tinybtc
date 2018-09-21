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

#define PREFIXED_HASH_KEY_LENGTH (SHA256_HEXSTR_LENGTH + 1)

enum Prefix {
    BLOCK_PREFIX = 'L',
    TX_PREFIX = 'T',
    TX_LOCATION_PREFIX = 'R',
};

typedef enum Prefix Prefix;

static bool file_exist(char *filename) {
    struct stat buffer;
    return stat(filename, &buffer) == 0;
}

int32_t save_peers_for_human() {
    FILE *file = fopen(PEER_LIST_CSV_FILENAME, "wb");

    for (uint64_t i = 0; i < global.peerCandidateCount; i++) {
        PeerCandidate *candidate = &global.peerCandidates[i];
        char *ipString = convert_ipv4_readable(candidate->addr.net_addr.ip);
        fprintf(
            file,
            "%u,%u,%s,%u,%llu,%.1f\n",
            candidate->status,
            candidate->addr.timestamp,
            ipString,
            ntohs(candidate->addr.net_addr.port),
            candidate->addr.net_addr.services,
            candidate->averageLatency
        );
    }
    fclose(file);

    return 0;
}

int32_t save_peer_candidates() {
    filter_peer_candidates();
    FILE *file = fopen(PEER_LIST_BINARY_FILENAME, "wb");

    uint8_t peerCountBytes[PEER_ADDRESS_COUNT_WIDTH] = { 0 };
    segment_uint32(global.peerCandidateCount, peerCountBytes);
    fwrite(peerCountBytes, sizeof(global.peerCandidateCount), 1, file);

    fwrite(
        &global.peerCandidates,
        global.peerCandidateCount,
        sizeof(PeerCandidate),
        file
    );

    printf("Saved %u peer candidates\n", global.peerCandidateCount);

    fclose(file);

    save_peers_for_human();
    return 0;
}

int32_t load_peer_candidates() {
    if (!file_exist(PEER_LIST_BINARY_FILENAME)) {
        fprintf(stderr, "Peer candidate file does not exist; skipping import\n");
        return -1;
    }
    printf("Loading peer candidates ");
    FILE *file = fopen(PEER_LIST_BINARY_FILENAME, "rb");

    Byte buffer[sizeof(PeerCandidate)] = {0};

    fread(&buffer, PEER_ADDRESS_COUNT_WIDTH, 1, file);
    global.peerCandidateCount = combine_uint32(buffer);
    printf("(%u peers to recover)...", global.peerCandidateCount);
    for (uint32_t index = 0; index < global.peerCandidateCount; index++) {
        fread(&buffer, 1, sizeof(PeerCandidate), file);
        memcpy(&global.peerCandidates[index], buffer, sizeof(PeerCandidate));
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
        leveldb_free(error);
        return -1;
    }
    leveldb_free(options);
    global.db = db;
    printf("Done.\n");
    return 0;
}

void cleanup_db() {
    leveldb_close(global.db);
}

int32_t save_block_indices(void) {
    FILE *file = fopen(BLOCK_INDICES_FILENAME, "wb");
    fwrite(&global.mainHeaderTip, sizeof(global.mainHeaderTip), 1, file);
    fwrite(&global.mainValidatedTip, sizeof(global.mainValidatedTip), 1, file);

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
    fread(&global.mainHeaderTip, sizeof(global.mainHeaderTip), 1, file);
    fread(&global.mainValidatedTip, sizeof(global.mainValidatedTip), 1, file);
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

int8_t save_data_by_hash(Byte *hash, Prefix prefix, Byte *value, uint64_t valueLength) {
    uint32_t keyLength = PREFIXED_HASH_KEY_LENGTH;
    char key[PREFIXED_HASH_KEY_LENGTH] = {0};
    key[0] = prefix;
    hash_binary_to_hex(hash, key+1);
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
        leveldb_free(error);
        return -1;
    }
    leveldb_free(writeOptions);
    return 0;
}

int8_t load_data_by_hash(Byte *hash, Prefix prefix, Byte *output, size_t *outputLength) {
    const uint32_t keyLength = PREFIXED_HASH_KEY_LENGTH;
    char key[PREFIXED_HASH_KEY_LENGTH] = {0};
    key[0] = prefix;
    hash_binary_to_hex(hash, key+1);

    size_t readLength = 0;
    char *error = NULL;
    leveldb_readoptions_t *readOptions = leveldb_readoptions_create();
    char *read = leveldb_get(
        global.db, readOptions,
        key, keyLength,
        &readLength,
        &error
    );
    leveldb_free(readOptions);

    if (read == NULL) {
        printf("leveldb: key not found %s\n", key);
        return -1;
    }
    else if (error != NULL) {
        leveldb_free(error);
        fprintf(stderr, "leveldb: Read fail on key %s\n", key);
        return -1;
    }
    memcpy(output, read, readLength);
    if (outputLength) {
        *outputLength = readLength;
    }
    return 0;
}

int8_t remove_data_by_hash(Byte *hash, Prefix prefix) {
    uint32_t keyLength = PREFIXED_HASH_KEY_LENGTH;
    char key[PREFIXED_HASH_KEY_LENGTH] = {0};
    key[0] = prefix;
    hash_binary_to_hex(hash, key+1);
    char *error = NULL;
    leveldb_writeoptions_t *writeOptions = leveldb_writeoptions_create();
    leveldb_delete(
        global.db, writeOptions,
        key, keyLength,
        &error
    );

    if (error != NULL) {
        fprintf(stderr, "Delete fail: %s\n", error);
        leveldb_free(error);
        return -1;
    }
    leveldb_free(writeOptions);
    return 0;
}

int8_t save_block(BlockPayload *ptrBlock) {
    SHA256_HASH hash = {0};
    hash_block_header(&ptrBlock->header, hash);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_block:buffer");
    uint64_t width = serialize_block_payload(ptrBlock, buffer);
    save_data_by_hash(hash, BLOCK_PREFIX, buffer, width);
    FREE(buffer, "save_block:buffer");
    return 0;
}

int8_t load_block(Byte *hash, BlockPayload *ptrBlock) {
    SHA256_HASH key = {0};
    memcpy(key, hash, SHA256_LENGTH);

    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_block:buffer");
    size_t outputLength = 0;
    int8_t status = load_data_by_hash(key, BLOCK_PREFIX, buffer, &outputLength);
    parse_into_block_payload(buffer, ptrBlock);
    SHA256_HASH actualHash = {0};
    Byte hashBuffer[1000] = {0};
    uint64_t width = serialize_block_payload_header(&ptrBlock->header, hashBuffer);
    dsha256(hashBuffer, (uint32_t)width, actualHash);
    if (memcmp(actualHash, hash, SHA256_LENGTH) != 0) {
        fprintf(stderr, "load_block: hashes mismatch for %li bytes\n", outputLength);
        print_hash_with_description("requested: ", hash);
        print_hash_with_description("actual: ", actualHash);
        mark_block_as_unavailable(hash);
        remove_data_by_hash(hash, BLOCK_PREFIX);
        status = ERROR_BAD_DATA;
    }
    else if (!is_block_legal(ptrBlock)) {
        fprintf(stderr, "load_block: fetched illegal block, probably DB corruption...\n");
        mark_block_as_unavailable(hash);
        remove_data_by_hash(hash, BLOCK_PREFIX);
        status = ERROR_BAD_DATA;
    }
    else {
        print_hash_with_description("load_block: OK ", hash);
    }
    FREE(buffer, "load_block:buffer");
    return status;
}

int8_t save_tx_location(TxPayload *ptrTx, Byte *blockHash) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_tx:buffer");
    uint64_t width = serialize_tx_payload(ptrTx, buffer);
    SHA256_HASH txHash = {0};
    dsha256(buffer, (uint32_t)width, txHash);
    save_data_by_hash(txHash, TX_LOCATION_PREFIX, blockHash, SHA256_LENGTH);
    FREE(buffer, "save_tx:buffer");
    return 0;
}

int8_t load_tx(Byte *targetHash, TxPayload *ptrPayload) {
    int8_t status = 0;
    SHA256_HASH blockHash = {0};
    size_t hashWidth = 0;
    status = load_data_by_hash(targetHash, TX_LOCATION_PREFIX, blockHash, &hashWidth);
    if (status) {
        fprintf(stderr, "Cannot load block reference\n");
    }

    size_t blockLength = 0;
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_tx:buffer");
    status = load_data_by_hash(blockHash, BLOCK_PREFIX, buffer, &blockLength);
    if (status) {
        fprintf(stderr, "Cannot load block itself\n");
    }
    BlockPayload *block = CALLOC(1, sizeof(*block), "load_tx:block");
    parse_into_block_payload(buffer, block);

    SHA256_HASH txHash = {0};
    for (uint64_t i = 0; i < block->txCount; i++) {
        uint64_t width = serialize_tx_payload(&block->txs[i], buffer);
        dsha256(buffer, (uint32_t)width, txHash);
        if (memcmp(txHash, targetHash, SHA256_LENGTH) == 0) {
            parse_into_tx_payload(buffer, ptrPayload);
            status = 0;
        }
    }

    release_block(block);
    FREE(buffer, "load_tx:buffer");
    return status;
}

uint64_t get_binary_keys_by_prefix(SHA256_HASH hashes[], Prefix desiredPrefix) {
    uint64_t count = 0;
    leveldb_readoptions_t *readOptions = leveldb_readoptions_create();
    leveldb_iterator_t *iter = leveldb_create_iterator(global.db, readOptions);
    for (leveldb_iter_seek_to_first(iter); leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
        size_t keyLength;
        const char *ptrKey = leveldb_iter_key(iter, &keyLength);
        if (keyLength != PREFIXED_HASH_KEY_LENGTH) {
            fprintf(stderr, "Unexpected key length %lu\n", keyLength);
            continue;
        }
        Prefix prefix = ptrKey[0];
        if (prefix != desiredPrefix) {
            continue;
        }
        SHA256_HASH hash = {0};
        sha256_hex_to_binary(ptrKey+1, hash);
        memcpy(hashes[count], hash, sizeof(hash));
        count++;
    }
    leveldb_free(readOptions);
    leveldb_free(iter);
    return count;
}

uint64_t get_hash_keys_of_blocks(SHA256_HASH *hashes) {
    return get_binary_keys_by_prefix(hashes, BLOCK_PREFIX);
}

void save_chain_data() {
    printf("Saving chain data...\n");
    save_peer_candidates();
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

void migrate() {
    hashmap_init(&global.blockIndices, (1UL << 25) - 1, SHA256_LENGTH);
    load_genesis();
    load_block_indices();
    Byte *keys = CALLOC(MAX_BLOCK_COUNT, SHA256_LENGTH, "recalculate_block_indices:keys");
    uint32_t indexCount = (uint32_t)hashmap_getkeys(&global.blockIndices, keys);
    for (uint32_t i = 0; i < indexCount; i++) {
        Byte key[SHA256_LENGTH] = {0};
        memcpy(key, keys + i * SHA256_LENGTH, SHA256_LENGTH);
        BlockIndex *ptrIndex = GET_BLOCK_INDEX(key);
        ptrIndex->meta.fullBlockAvailable = false;
        ptrIndex->meta.fullBlockValidated = false;
    }
    BlockIndex *genesisIndex = GET_BLOCK_INDEX(global.genesisHash);
    global.mainValidatedTip = *genesisIndex;
    global.mainHeaderTip = *genesisIndex;
    save_block_indices();
}

