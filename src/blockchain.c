#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "blockchain.h"
#include "globalstate.h"
#include "hash.h"
#include "util.h"

void expand_target(
    uint32_t targetBits,
    Byte *bytes
) {
    Byte targetBytes[sizeof(targetBits)] = {0};
    segment_uint32(targetBits, targetBytes);
    int32_t initial_zero_digits = targetBytes[3] - 3;

    memset(bytes, 0, SHA256_LENGTH);
    memcpy(bytes + initial_zero_digits, targetBytes, sizeof(targetBytes) - 1);
}

int8_t hashcmp(
    const Byte *hashA,
    const Byte *hashB,
    uint32_t width
) {
    for (uint32_t i = width - 1; i >= 0; i--) {
        if (hashA[i] < hashB[i]) {
            return -1;
        }
        if (hashA[i] > hashB[i]) {
            return 1;
        }
    }
    return 0;
}

bool hash_satisfies_target(
    const Byte *hash,
    const Byte *target
) {
    return hashcmp(hash, target, SHA256_LENGTH) < 0;
}

void relocate_main_chain() {
    printf("Relocating main chain...\n");
    Byte *keys = calloc(1000000, SHA256_LENGTH);

    bool tipEverMoved = false;
    bool foundNewTip;
    do {
        foundNewTip = false;
        BlockPayloadHeader *ptrNextTip = hashmap_get(&global.headersByPrevBlock, global.mainChainTip, NULL);
        if (ptrNextTip) {
            SHA256_HASH hash = {0};
            dsha256(ptrNextTip, sizeof(*ptrNextTip), hash);
            memcpy(global.mainChainTip, hash, SHA256_LENGTH);
            tipEverMoved = true;
            foundNewTip = true;
            global.mainChainHeight += 1;
        }
    } while (foundNewTip);
    if (tipEverMoved) {
        printf("Main chain tip moved to (BE)");
    }
    else {
        printf("Main chain tip remained at (BE)");
    }
    print_sha256_reverse(global.mainChainTip);
    printf(" (height=%u)\n", global.mainChainHeight);
    free(keys);
}
