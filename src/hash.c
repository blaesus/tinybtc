#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
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

static void fprint_hex_reverse_of_width(FILE *stream, Byte *data, uint64_t length) {
    for (uint64_t i = length; i > 0; i--) {
        fprintf(stream, "%02x", data[i-1]);
    }
}

char *binary_to_hexstr(Byte *data, uint64_t length) {
    static char s[1024] = {0};
    memset(s, 0, sizeof(s));
    for (uint64_t i = length; i > 0; i--) {
        sprintf(&s[(length - i) * 2], "%02x", data[i-1]);
    }
    return s;
}

static void print_hex_reverse_of_width(Byte *data, uint64_t length) {
    fprint_hex_reverse_of_width(stdout, data, length);
}

void print_sha256(Byte *hash) {
    print_hex_of_width(hash, SHA256_LENGTH);
}

void fprint_sha256_reverse(FILE *stream, Byte *hash)  {
    fprintf(stream, "(BE)");
    fprint_hex_reverse_of_width(stream, hash, SHA256_LENGTH);
}

void print_sha256_reverse(Byte *hash) {
    printf("(BE)");
    print_hex_reverse_of_width(hash, SHA256_LENGTH);
}

void fprint_hash_with_description(FILE *stream, char *description, Byte *hash) {
    fprintf(stream, "%s", description);
    fprint_sha256_reverse(stream, hash);
    fprintf(stream, "\n");
}

void print_hash_with_description(char *description, Byte *hash) {
    fprint_hash_with_description(stdout, description, hash);
}

void print_hash_with_error(char *description, Byte *hash) {
    fprintf(stderr, "%s", description);
    print_sha256_reverse(hash);
    fprintf(stderr, "\n");
}

void print_sha256_short(Byte *hash) {
    print_hex_of_width(hash, 8);
}

bool is_hash_empty(Byte *hash) {
    SHA256_HASH empty = {0};
    return sha256_match(hash, empty);
}

void ripemd(void *data, uint32_t length, RIPEMD_HASH result) {
    RIPEMD160_CTX context;
    RIPEMD160_Init(&context);
    RIPEMD160_Update(&context, data, length);
    RIPEMD160_Final(result, &context);
}

void sharipe(void *data, uint32_t length, RIPEMD_HASH result) {
    SHA256_HASH sha256Hash;
    sha256(data, length, sha256Hash);
    ripemd(sha256Hash, SHA256_LENGTH, result);
}

void sha256_hex_to_binary(const char *str, Byte *hash) {
    char byteString[3] = {0};
    for (uint16_t i = 0; i < SHA256_LENGTH; i++) {
        memcpy(byteString, str + 2*i, 2);
        Byte byteDigit = (Byte)strtol(byteString, NULL, 16);
        hash[i] = byteDigit;
    }
}


void hash_binary_to_hex(Byte *hash, char *hex) {
    for (uint32_t i = 0; i < 32; i++) {
        sprintf(hex+2*i, "%02x", hash[i]);
    }
}

bool sha256_match(Byte *hashA, Byte *hashB) {
    return memcmp(hashA, hashB, SHA256_LENGTH) == 0;
}

void sha1(void *data, uint32_t length, SHA1_HASH result) {
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, data, length);
    SHA1_Final(result, &context);
}
