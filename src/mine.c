#include <stdint.h>
#include <sys/time.h>

#include "messages/block.h"
#include "util.h"
#include "mine.h"
#include "blockchain.h"

#define LOG_INTERVAL 1000000


uint32_t mine_block_header(
    BlockPayloadHeader header,
    uint32_t initialNonce,
    char *processLabel
) {
    SHA256_HASH hash = {0xFF};
    header.nonce = initialNonce;
    struct timeval timer;
    gettimeofday(&timer, NULL);
    SHA256_HASH targethash = {0};
    expand_target(header.target_bits, targethash);
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
        if ((hash_satisfies_target(hash, targethash))) {
            printf("Found nonce=%u", header.nonce);
            print_object(hash, SHA256_LENGTH);
            break;
        }
    }
    return header.nonce;
}
