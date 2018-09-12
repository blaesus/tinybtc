#include <stdio.h>
#include <unistd.h>
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include "datatypes.h"
#include "hash.h"

void sha256(void *data, uint32_t length, SHA256_HASH result) {
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, data, length);
    SHA256_Final(result, &context);
}

void dsha256(void *data, uint32_t length, SHA256_HASH result) {
    SHA256_HASH firstRoundResult = {0};
    sha256(data, length, firstRoundResult);
    sha256(firstRoundResult, SHA256_LENGTH, result);
}

static void print_hex_of_width(Byte *data, uint64_t length) {
    for (uint64_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
}

static void print_hex_reverse_of_width(Byte *data, uint64_t length) {
    for (uint64_t i = length; i > 0; i--) {
        printf("%02x", data[i-1]);
    }
}

void print_sha256(Byte *hash) {
    print_hex_of_width(hash, SHA256_LENGTH);
}

void print_sha256_reverse(Byte *hash) {
    printf("(BE)");
    print_hex_reverse_of_width(hash, SHA256_LENGTH);
}

void print_hash_with_description(char *description, Byte *hash) {
    printf("%s", description);
    print_sha256_reverse(hash);
    printf("\n");
}

void print_sha256_short(Byte *hash) {
    print_hex_of_width(hash, 8);
}

bool is_hash_empty(Byte *hash) {
    SHA256_HASH empty = {0};
    return memcmp(hash, empty, SHA256_LENGTH) == 0;
}
void sharipe(void *data, uint32_t length, SHA256_HASH result) {
    SHA256_HASH sha256Hash;
    sha256(data, length, sha256Hash);
    RIPEMD160_CTX context;
    RIPEMD160_Init(&context);
    RIPEMD160_Update(&context, sha256Hash, SHA256_LENGTH);
    RIPEMD160_Final(result, &context);
}
