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


void targetCompactToBignum(TargetCompact targetBytes, BIGNUM *ptrTarget) {
    unsigned int nSize = targetBytes >> 24;
    Byte vch[64] = {0};
    vch[3] = nSize;
    if (nSize >= 1) vch[4] = (targetBytes >> 16) & 0xff;
    if (nSize >= 2) vch[5] = (targetBytes >> 8) & 0xff;
    if (nSize >= 3) vch[6] = (targetBytes >> 0) & 0xff;
    BN_mpi2bn(&vch[0], 4 + nSize, ptrTarget);
}

uint32_t targetBignumToCompact(BIGNUM *ptrTarget) {
    uint32_t nSize = (uint32_t) BN_bn2mpi(ptrTarget, NULL);
    Byte vch[64] = {0};
    nSize -= 4;
    BN_bn2mpi(ptrTarget, &vch[0]);
    uint32_t nCompact = nSize << 24;
    if (nSize >= 1) nCompact |= (vch[4] << 16);
    if (nSize >= 2) nCompact |= (vch[5] << 8);
    if (nSize >= 3) nCompact |= (vch[6] << 0);
    return nCompact;
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
    for (uint32_t tracer = 0; tracer < mainnet.retargetLookBackPeriod - 1; tracer++) {
        BlockPayloadHeader *p = hashmap_get(
            &global.headers, ptrRetargetPeriodStart, NULL
        );
        ptrRetargetPeriodStart = p->prev_block;
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
    printf("time difference in retarget period: %2.8f days\n", 1.0 * actualPeriod / DAY(1));
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
        targetCompactToBignum(global.mainChainTarget, newTarget);
        BN_mul_word(newTarget, actualPeriod);
        BN_div_word(newTarget, mainnet.desiredRetargetPeriod);
        global.mainChainTarget = targetBignumToCompact(newTarget);
    }
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
