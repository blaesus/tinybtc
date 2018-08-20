#include <stdint.h>
#include <sys/time.h>

#include "messages/block.h"
#include "util.h"
#include "mine.h"

#define LOG_INTERVAL 1000000

bool is_hash_passable(const SHA256_HASH hash) {
    return hash[31] == 0 && hash[30] == 0 && hash[29] == 0 && hash[28] == 0 && hash[27] == 0;
}

uint32_t mine_header(
    BlockPayloadHeader header,
    uint32_t initialNonce,
    char *processLabel
) {
    SHA256_HASH hash = {0xFF};
    header.nonce = initialNonce;
    struct timeval timer;
    gettimeofday(&timer, NULL);
    while (true) {
        header.nonce++;
        dsha256(&header, sizeof(header), hash);
        if (header.nonce % LOG_INTERVAL == 0) {
            int64_t oldSec = timer.tv_sec;
            int64_t oldMicroSec = timer.tv_usec;
            gettimeofday(&timer, NULL);
            int64_t newSec = timer.tv_sec;
            int64_t newMicroSec = timer.tv_usec;
            double delta = (newSec - oldSec) + (newMicroSec - oldMicroSec) / 1e6;

            printf("%s: trying nonce %u (%1.3lfs)\n", processLabel, header.nonce, delta);
        }
        if (is_hash_passable(hash)) {
            printf("Found nonce=%u", header.nonce);
            print_object(hash, SHA256_LENGTH);
            break;
        }
    }
    return header.nonce;
}
