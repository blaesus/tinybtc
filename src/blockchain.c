#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#include "blockchain.h"
#include "globalstate.h"
#include "hash.h"
#include "util.h"
#include "units.h"

void target_4to32(uint32_t targetBytes, Byte *bytes) {
    int32_t exponentWidth = (targetBytes >> 24) - 3;
    memset(bytes, 0, SHA256_LENGTH);
    memcpy(bytes + exponentWidth, &targetBytes, TARGET_BITS_MANTISSA_WIDTH);
}

long double pow256(long double x) {
    return powl(2, x * 8);
}

long double log256(long double x) {
    return log2l(x) / 8;
}

long double targetQuodToRoughDouble(TargetCompact targetBytes) {
    uint32_t exponentWidth = targetBytes >> 24;
    exponentWidth -= 3;
    uint32_t mantissa =
        + ((targetBytes >> 16) & 0xff) * 65536
        + ((targetBytes >> 8) & 0xff) * 256
        + (targetBytes & 0xff);
    return mantissa * pow256(exponentWidth);
}

// Compact-Bignum conversion adapted from Bitcoin 0.0.1 by Satoshi

void targetCompactToBignum(TargetCompact targetBytes, BIGNUM *ptrTarget) {
    uint32_t size = targetBytes >> 24;
    Byte inputBytes[64] = {0};
    inputBytes[3] = (Byte)size;
    if (size >= 1) inputBytes[4] = (Byte)((targetBytes >> 16) & 0xff);
    if (size >= 2) inputBytes[5] = (Byte)((targetBytes >> 8) & 0xff);
    if (size >= 3) inputBytes[6] = (Byte)((targetBytes >> 0) & 0xff);
    BN_mpi2bn(&inputBytes[0], 4 + size, ptrTarget);
}

uint32_t targetBignumToCompact(BIGNUM *ptrTarget) {
    uint32_t size = (uint32_t)BN_bn2mpi(ptrTarget, NULL);
    Byte outputBytes[64] = {0};
    size -= 4;
    BN_bn2mpi(ptrTarget, &outputBytes[0]);
    uint32_t result = size << 24;
    if (size >= 1) result |= (outputBytes[4] << 16);
    if (size >= 2) result |= (outputBytes[5] << 8);
    if (size >= 3) result |= (outputBytes[6] << 0);
    return result;
}

bool hash_satisfies_target(
    const Byte *hash,
    const Byte *target
) {
    return bytescmp(hash, target, SHA256_LENGTH) < 0;
}

bool is_block_header_legal_as_tip(
    BlockPayloadHeader *ptrHeader
) {
    bool timestampLegal =
        (int64_t)ptrHeader->timestamp - time(NULL) < mainnet.blockMaxForwardTimestamp;

    SHA256_HASH hash = {0};
    dsha256(ptrHeader, sizeof(*ptrHeader), hash);
    ByteArray32 target = {0};
    target_4to32(global.mainChainTarget, target);
    bool hashLegal = hash_satisfies_target(hash, target);

    return timestampLegal && hashLegal;
}

static void retarget() {
    printf("\n=== Retarget ===\n");
    printf("main height = %i \n", global.mainChainHeight);
    print_tip_with_description(
        "Retargeting from tip ", global.mainChainTip
    );
    Byte *ptrRetargetPeriodStart = global.mainChainTip;
    for (uint32_t tracer = 0; ptrRetargetPeriodStart && tracer < mainnet.retargetLookBackPeriod; tracer++) {
        BlockPayloadHeader *ptrBlockHeader = hashmap_get(
            &global.headers, ptrRetargetPeriodStart, NULL
        );
        ptrRetargetPeriodStart = ptrBlockHeader->prev_block;
    }
    print_tip_with_description(
        "Retarget period initial node tracked back to ", ptrRetargetPeriodStart
    );
    BlockPayloadHeader *ptrRetargetStartNode = hashmap_get(
        &global.headers, ptrRetargetPeriodStart, NULL
    );
    BlockPayloadHeader *ptrRetargetEndNode = hashmap_get(
        &global.headers, global.mainChainTip, NULL
    );
    uint32_t actualPeriod = ptrRetargetEndNode->timestamp - ptrRetargetStartNode->timestamp;
    printf(
        "time difference in retarget period: %u seconds (%2.1f days) [from %u, to %u]\n",
        actualPeriod,
        1.0 * actualPeriod / DAY(1),
        ptrRetargetEndNode->timestamp,
        ptrRetargetStartNode->timestamp
    );
    uint32_t multiplier = actualPeriod;
    if (multiplier < mainnet.desiredRetargetPeriod / 4) {
        multiplier = mainnet.desiredRetargetPeriod / 4;
    }
    if (multiplier > mainnet.desiredRetargetPeriod * 4) {
        multiplier = mainnet.desiredRetargetPeriod * 4;
    }
    long double ratio = (double)actualPeriod / (double)mainnet.desiredRetargetPeriod;
    const long double MAX_TARGET = targetQuodToRoughDouble(global.genesisBlock.header.target);
    long double currentTargetFloat = targetQuodToRoughDouble(global.mainChainTarget);
    long double nextTargetFloat = currentTargetFloat * ratio;
    if (nextTargetFloat > MAX_TARGET) {
        printf("Next target hitting ceiling, using ceiling instead\n");
        global.mainChainTarget = global.genesisBlock.header.target;
    }
    else {
        long double difficulty = MAX_TARGET / nextTargetFloat;
        printf("retarget: %.3Le -> %.3Le (difficulty %.2Lf)\n", currentTargetFloat, nextTargetFloat, difficulty);
        BIGNUM *newTarget = BN_new();
        targetCompactToBignum(ptrRetargetEndNode->target, newTarget);
        BN_mul_word(newTarget, multiplier);
        BN_div_word(newTarget, mainnet.desiredRetargetPeriod);
        global.mainChainTarget = targetBignumToCompact(newTarget);
    }
    printf("New target %u (%x)\n", global.mainChainTarget, global.mainChainTarget);
    printf("=============\n");
}

static void update_target() {
    // e.g. Retarget after block 2015 is made, i.e. adjusting target for
    // the incoming 2016 block
    bool shouldRetarget =
        (global.mainChainHeight + 1) % mainnet.retargetPeriod == 0;
    if (shouldRetarget) {
        retarget();
    }
}

void relocate_main_chain() {
    printf("Relocating main chain...\n");
    Byte *keys = calloc(1000000, SHA256_LENGTH);

    bool tipEverMoved = false;
    bool foundNewTip;
    do {
        foundNewTip = false;
        update_target();
        BlockPayloadHeader *ptrNextTip = hashmap_get(&global.headersByPrevBlock, global.mainChainTip, NULL);
        if (ptrNextTip) {
            if (!is_block_header_legal_as_tip(ptrNextTip)) {
                printf("Illegal header (timestamped %u), skipping\n", ptrNextTip->timestamp);
                continue;
            }
            SHA256_HASH hash = {0};
            dsha256(ptrNextTip, sizeof(*ptrNextTip), hash);
            memcpy(global.mainChainTip, hash, SHA256_LENGTH);
            tipEverMoved = true;
            foundNewTip = true;
            global.mainChainHeight += 1;
        }
    } while (foundNewTip);
    if (tipEverMoved) {
        printf("Main chain tip moved to ");
    }
    else {
        printf("Main chain tip remained at ");
    }
    print_sha256_reverse(global.mainChainTip);
    printf(" (height=%u)\n", global.mainChainHeight);
    free(keys);
}
