#include "sha256/sha256.h"
#include "hash.h"

void sha256(void *data, uint32_t length, SHA256_HASH result) {
    SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, result);
}

void dsha256(void *data, uint32_t length, SHA256_HASH result) {
    SHA256_HASH firstRoundResult = {0};
    sha256(data, length, firstRoundResult);
    sha256(firstRoundResult, SHA256_LENGTH, result);
}
