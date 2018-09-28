#include <stdio.h>
#include <stdlib.h>
#include "leveldb/c.h"

#include "persistent.h"

#include "globalstate.h"
#include "blockchain.h"
#include "config.h"
#include "utils/integers.h"
#include "utils/memory.h"
#include "utils/networking.h"
#include "utils/data.h"
#include "utils/file.h"

#define MAX_PATH_LENGTH 256

#define ARCHIVE_ROOT "archive"
#define BLOCK_ROOT "blocks"

#define PEER_LIST_BINARY_FILENAME (ARCHIVE_ROOT"/peers.dat")
#define PEER_LIST_CSV_FILENAME (ARCHIVE_ROOT"/peers.csv")

#define BLOCK_INDEX_PATH (ARCHIVE_ROOT"/block_indices.dat")

#define HASH_KEY_STRING_LENGTH (SHA256_HEXSTR_LENGTH + 1)

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
    printf("Connecting to databases...");
    leveldb_options_t *options = leveldb_options_create();
    leveldb_options_set_create_if_missing(options, 1);
    char *error = NULL;
    char txLocationPath[MAX_PATH_LENGTH] = {0};
    sprintf(txLocationPath, "%s/%s", ARCHIVE_ROOT, config.txLocationDBName);
    global.txLocationDB = leveldb_open(options, txLocationPath, &error);
    if (error != NULL) {
        fprintf(stderr, "Open LevelDB fail: %s\n", error);
        leveldb_free(error);
        return -1;
    }
    char utxoDBPath[MAX_PATH_LENGTH] = {0};
    sprintf(utxoDBPath, "%s/%s", ARCHIVE_ROOT, config.utxoDBName);
    global.utxoDB = leveldb_open(options, utxoDBPath, &error);
    if (error != NULL) {
        fprintf(stderr, "Open LevelDB fail: %s\n", error);
        leveldb_free(error);
        return -2;
    }
    leveldb_free(options);
    printf("Done.\n");
    return 0;
}

void cleanup_db() {
    leveldb_close(global.txLocationDB);
    leveldb_close(global.utxoDB);
}

int32_t save_block_indices(void) {
    FILE *file = fopen(BLOCK_INDEX_PATH, "wb");
    fwrite(&global.mainHeaderTip, sizeof(global.mainHeaderTip), 1, file);
    fwrite(&global.mainValidatedTip, sizeof(global.mainValidatedTip), 1, file);

    Byte *keys = CALLOC(MAX_BLOCK_COUNT, SHA256_LENGTH, "save_block_indices:keys");
    uint32_t keyCount = (uint32_t)hashmap_getkeys(&global.blockIndices, keys);
    printf("Saving %u block indices to %s...\n", keyCount, BLOCK_INDEX_PATH);
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
    if (!file_exist(BLOCK_INDEX_PATH)) {
        fprintf(stderr, "block index file does not exist; skipping import\n");
        return -1;
    }
    FILE *file = fopen(BLOCK_INDEX_PATH, "rb");
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

int8_t save_data_by_key(leveldb_t *db, char *key, Byte *value, uint64_t valueLength) {
    char *error = NULL;
    leveldb_writeoptions_t *writeOptions = leveldb_writeoptions_create();
    leveldb_put(
        db, writeOptions,
        key, strlen(key),
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

int8_t save_data_by_hash(leveldb_t *db, Byte *hash, Byte *value, uint64_t valueLength) {
    char key[HASH_KEY_STRING_LENGTH] = {0};
    hash_binary_to_hex(hash, key);
    save_data_by_key(db, key, value, valueLength);
    return save_data_by_key(db, key, value, valueLength);
}

int8_t load_data_by_key(leveldb_t *db, char *key, Byte *output, size_t *outputLength) {
    size_t readLength = 0;
    char *error = NULL;
    leveldb_readoptions_t *readOptions = leveldb_readoptions_create();
    char *read = leveldb_get(
        db, readOptions,
        key, strlen(key),
        &readLength,
        &error
    );
    leveldb_free(readOptions);

    if (read == NULL) {
        fprintf(stderr, "leveldb: key not found %s\n", key);
        return -1;
    }
    else if (error != NULL) {
        leveldb_free(error);
        fprintf(stderr, "leveldb: Read fail on key %s\n", key);
        return -2;
    }
    memcpy(output, read, readLength);
    if (outputLength) {
        *outputLength = readLength;
    }
    return 0;
}

int8_t load_data_by_hash(leveldb_t *db, Byte *hash, Byte *output, size_t *outputLength) {
    char key[HASH_KEY_STRING_LENGTH] = {0};
    hash_binary_to_hex(hash, key);
    return load_data_by_key(db, key, output, outputLength);
}

int8_t remove_data_by_key(leveldb_t *db, char *key) {
    char *error = NULL;
    leveldb_writeoptions_t *writeOptions = leveldb_writeoptions_create();
    leveldb_delete(
        db, writeOptions,
        key, strlen(key),
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

int8_t remove_data_by_hash(leveldb_t *db, Byte *hash) {
    char key[HASH_KEY_STRING_LENGTH] = {0};
    hash_binary_to_hex(hash, key);
    return remove_data_by_key(db, key);
}

char *make_entity_path(char *collectionRoot, Byte *hash) {
    char hashHex[HASH_KEY_STRING_LENGTH] = {0};
    hash_binary_to_hex(hash, hashHex);
    static char path[MAX_PATH_LENGTH];
    memset(path, 0, sizeof(path));
    char x[3] = {0};
    memcpy(x, hashHex, 2);
    sprintf(path, "%s/%s/%s/%s.dat", ARCHIVE_ROOT, collectionRoot, x, hashHex);
    return path;
}

int8_t save_block(BlockPayload *ptrBlock) {
    SHA256_HASH hash = {0};
    hash_block_header(&ptrBlock->header, hash);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_block:buffer");
    uint64_t serializedWidth = serialize_block_payload(ptrBlock, buffer);
    FILE *file = fopen(make_entity_path(BLOCK_ROOT, hash), "wb");
    if (!file) {
        fprintf(stderr, "save_block: cannot open file: %s\n", strerror(errno));
        return -1;
    }
    fwrite(buffer, serializedWidth, 1, file);
    fclose(file);
    FREE(buffer, "save_block:buffer");
    return 0;
}

int8_t load_block(Byte *hash, BlockPayload *ptrBlock) {
    SHA256_HASH key = {0};
    memcpy(key, hash, SHA256_LENGTH);

    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_block:buffer");
    int8_t status = 0;
    FILE *file = fopen(make_entity_path(BLOCK_ROOT, hash), "rb");
    if (!file) {
        fprintf(stderr, "load_block: Cannot open file\n");
        return -99;
    }
    int64_t fileSize = get_file_size(file);
    fread(buffer, (size_t)fileSize, 1, file);
    fclose(file);

    parse_into_block_payload(buffer, ptrBlock);
    SHA256_HASH actualHash = {0};
    Byte hashBuffer[1000] = {0};
    uint64_t width = serialize_block_payload_header(&ptrBlock->header, hashBuffer);
    dsha256(hashBuffer, (uint32_t)width, actualHash);
    if (memcmp(actualHash, hash, SHA256_LENGTH) != 0) {
        #if LOG_BLOCK_LOAD
        fprintf(stderr, "load_block: hashes mismatch for %lli bytes\n", fileSize);
        #endif
        print_hash_with_description("requested: ", hash);
        print_hash_with_description("actual: ", actualHash);
        mark_block_as_unavailable(hash);
        status = ERROR_BAD_DATA;
    }
    else if (!is_block_legal(ptrBlock)) {
        #if LOG_BLOCK_LOAD
        fprintf(stderr, "load_block: fetched illegal block, probably file corruption...\n");
        #endif
        mark_block_as_unavailable(hash);
        status = ERROR_BAD_DATA;
    }
    else {
        #if LOG_BLOCK_LOAD
        print_hash_with_description("load_block: OK ", hash);
        #endif
    }
    FREE(buffer, "load_block:buffer");
    return status;
}

int8_t save_tx_location(TxPayload *ptrTx, Byte *blockHash) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_tx:buffer");
    uint64_t width = serialize_tx_payload(ptrTx, buffer);
    SHA256_HASH txHash = {0};
    dsha256(buffer, (uint32_t)width, txHash);
    FREE(buffer, "save_tx:buffer");
    save_data_by_hash(global.txLocationDB, txHash, blockHash, SHA256_LENGTH);
    return 0;
}

int8_t load_tx(Byte *targetHash, TxPayload *ptrPayload) {
    int8_t status = 0;
    SHA256_HASH blockHash = {0};
    size_t hashWidth = 0;
    BlockPayload *block = CALLOC(1, sizeof(*block), "load_tx:block");
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_tx:buffer");
    status = load_data_by_hash(global.txLocationDB, targetHash, blockHash, &hashWidth);
    if (status) {
        fprintf(stderr, "Cannot load block reference\n");
        goto release;
    }

    status = load_block(blockHash, block);
    if (status) {
        fprintf(stderr, "Cannot load block itself\n");
        goto release;
    }

    SHA256_HASH txHash = {0};
    for (uint64_t i = 0; i < block->txCount; i++) {
        uint64_t width = serialize_tx_payload(&block->txs[i], buffer);
        dsha256(buffer, (uint32_t)width, txHash);
        bool hashesMatch = memcmp(txHash, targetHash, SHA256_LENGTH) == 0;
        if (hashesMatch) {
            parse_into_tx_payload(buffer, ptrPayload);
            status = 0;
        }
    }

    release:
    release_block(block);
    FREE(buffer, "load_tx:buffer");
    return status;
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

void checked_mkdir(char *path) {
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(path, &st) == -1) {
        mkdir(path, 0744);
    }
}

int8_t destory_db(char *dbname) {
    printf("Destorying database %s\n", dbname);
    leveldb_options_t *options = leveldb_options_create();
    char *error = NULL;
    leveldb_destroy_db(options, dbname, &error);
    if (error != NULL) {
        fprintf(stderr, "Database destruction: fail: %s\n", error);
        leveldb_free(error);
        return -1;
    }
    printf("Done destructing.\n");
    return 0;
}

void init_archive_dir() {
    checked_mkdir(ARCHIVE_ROOT);
    char blockRoot[MAX_PATH_LENGTH] = {0};
    sprintf(blockRoot, "%s/%s", ARCHIVE_ROOT, BLOCK_ROOT);
    checked_mkdir(blockRoot);

    for (uint16_t i = 0; i < 0x100; i++) {
        char path[MAX_PATH_LENGTH] = {0};
        sprintf(path, "%s/%s/%02x", ARCHIVE_ROOT, BLOCK_ROOT, i);
        checked_mkdir(path);
    }
}

void init_block_index_map() {
    hashmap_init(&global.blockIndices, (1UL << 25) - 1, SHA256_LENGTH);
}

#define UINT32_DECIMAL_MAX_WIDTH 10

#define TXO_KEY_LENGTH (HASH_KEY_STRING_LENGTH + 1 + UINT32_DECIMAL_MAX_WIDTH)

void make_txo_key(Outpoint *outpoint, char *key) {
    hash_binary_to_hex(outpoint->txHash, key);
    sprintf(key+HASH_KEY_STRING_LENGTH-1, "_%010u", outpoint->index);
}

int8_t save_utxo(Outpoint *outpoint, TxOut *output) {
    char key[TXO_KEY_LENGTH] = {0};
    make_txo_key(outpoint, key);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "save_utxo:buffer");
    uint64_t width = serialize_tx_out(output, buffer);
    int8_t status = save_data_by_key(global.utxoDB, key, buffer, width);
    FREE(buffer, "save_utxo:buffer");
    return status;
}

int8_t load_utxo(Outpoint *outpoint, TxOut *output) {
    char key[TXO_KEY_LENGTH] = {0};
    make_txo_key(outpoint, key);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "load_utxo:buffer");
    size_t width = 0;
    int8_t status = load_data_by_key(global.utxoDB, key, buffer, &width);
    parse_tx_out(buffer, output);
    FREE(buffer, "load_utxo:buffer");
    return status;
}


int8_t spend_output(Outpoint *outpoint) {
    char key[TXO_KEY_LENGTH] = {0};
    make_txo_key(outpoint, key);
    return remove_data_by_key(global.utxoDB, key);
}

bool is_outpoint_available(Outpoint *outpoint) {
    char key[TXO_KEY_LENGTH] = {0};
    make_txo_key(outpoint, key);
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "is_outpoint_spent:buffer");
    size_t resultWidth = 0;
    int8_t loadError = load_data_by_key(global.utxoDB, key, buffer, &resultWidth);
    FREE(buffer, "is_outpoint_spent:buffer");
    if (loadError) {
        fprintf(stderr, "is_txo_spent: Cannot load data\n");
        return false;
    }
    return true;
}

void migrate() {
}

