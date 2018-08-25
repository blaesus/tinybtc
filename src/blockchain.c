#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#include "gmp.h"

#include "blockchain.h"
#include "globalstate.h"
#include "hash.h"
#include "util.h"
#include "units.h"

void target_4to32(Byte *targetBytes, Byte *bytes) {
    int32_t exponentWidth = targetBytes[TARGET_BITS_MANTISSA_WIDTH] - TARGET_BITS_MANTISSA_WIDTH;
    memset(bytes, 0, SHA256_LENGTH);
    memcpy(bytes + exponentWidth, targetBytes, TARGET_BITS_MANTISSA_WIDTH);
}

long double pow256(long double x) {
    return powl(2, x * 8);
}

long double log256(long double x) {
    return log2l(x) / 8;
}

long double targetQuodToRoughDouble(Byte *targetBytes) {
    int32_t exponentWidth = targetBytes[TARGET_BITS_MANTISSA_WIDTH] - TARGET_BITS_MANTISSA_WIDTH;
    uint32_t mantissa =
        + (targetBytes[2] << 2 * BITS_IN_BYTE)
        + (targetBytes[1] << 1 * BITS_IN_BYTE)
        + (targetBytes[0]);
    return mantissa * pow256(exponentWidth);
}

void targetQuodToMpz(Byte *targetBytes, mpz_t targetMpz) {
    uint32_t exponentInt =
        (uint32_t)(targetBytes[TARGET_BITS_MANTISSA_WIDTH] - TARGET_BITS_MANTISSA_WIDTH);
    printf("Exponent %u\n", exponentInt);

    uint32_t mantissaInt =
        + (targetBytes[2] << 2 * BITS_IN_BYTE)
        + (targetBytes[1] << 1 * BITS_IN_BYTE)
        + (targetBytes[0]);
    printf("Mantissa %u\n", mantissaInt);

    mpz_t powerMpz;
    mpz_init(powerMpz);
    mpz_ui_pow_ui(powerMpz, 256, exponentInt);

    mpz_mul_ui(targetMpz, powerMpz, mantissaInt);
    mpz_clear(powerMpz);
}

uint64_t get_mantissa(uint32_t exponentInt, mpz_t targetMpz) {
    mpz_t mantissaMpz;
    mpz_init_set_ui(mantissaMpz, 0);

    mpz_t power;
    mpz_init_set_ui(power, 1);
    mpz_ui_pow_ui(power, 256, exponentInt - TARGET_BITS_MANTISSA_WIDTH);
    mpz_div(mantissaMpz, targetMpz, power);
    gmp_printf("Mantissa %Zd | target=%Zd, power=%Zd\n", mantissaMpz, targetMpz, power);

    mpz_clear(power);

    return mpz_get_ui(mantissaMpz);
}

void targetMpzToQuod(mpz_t targetMpz, Byte *targetBytes) {
    uint32_t exponentInt = 0;
    mpz_t power;
    mpz_init_set_ui(power, 1);
    while (mpz_cmp(power, targetMpz) < 0) {
        mpz_ui_pow_ui(power, 256, exponentInt);
        exponentInt++;
    }
    printf("Exponent %u\n", exponentInt);
    targetBytes[3] = (Byte)exponentInt;

    uint64_t mantissaInt = 0;
    // Maximize significand
    while (mantissaInt < 0xffff) {
        printf("move exponent from %u to %u\n", exponentInt, exponentInt - 1);
        exponentInt--;
        mantissaInt = get_mantissa(exponentInt, targetMpz);
    }
    targetBytes[0] = (uint8_t)(mantissaInt & 0xFF);
    targetBytes[1] = (uint8_t)((mantissaInt >> 1 * BITS_IN_BYTE) & 0xFF);
    targetBytes[2] = (uint8_t)((mantissaInt >> 2 * BITS_IN_BYTE) & 0xFF);

    mpz_clear(power);
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
        (int64_t)ptrHeader->timestamp - time(NULL) < parameters.blockMaxForwardTimestamp;

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
    for (uint32_t tracer = 0; tracer < parameters.retargetLookBackPeriod - 1; tracer++) {
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
    long double ratio = (double)actualPeriod / (double)parameters.desiredRetargetPeriod;
    const long double MAX_TARGET = targetQuodToRoughDouble(global.genesisBlock.header.target);
    long double currentTargetFloat = targetQuodToRoughDouble(global.mainChainTarget);
    long double nextTargetFloat = currentTargetFloat * ratio;
    if (nextTargetFloat > MAX_TARGET) {
        printf("Next target hitting ceiling, using ceiling instead\n");
        memcpy(global.mainChainTarget, global.genesisBlock.header.target, sizeof(TargetQuodBytes));
    }
    else {
        long double difficulty = MAX_TARGET / nextTargetFloat;
        printf("retarget: %.3Le -> %.3Le (difficulty %.2Lf)\n", currentTargetFloat, nextTargetFloat, difficulty);

        mpz_t currentTargetPrecise;
        mpz_init(currentTargetPrecise);
        targetQuodToMpz(global.mainChainTarget, currentTargetPrecise);

        mpz_t newTargetPrecise;
        mpz_init(newTargetPrecise);
        mpz_mul_ui(newTargetPrecise, currentTargetPrecise, actualPeriod);
        mpz_div_ui(newTargetPrecise, newTargetPrecise, parameters.desiredRetargetPeriod);
        gmp_printf("new target=%Zd\n", newTargetPrecise);

        TargetQuodBytes newTargetQuod = {0};
        targetMpzToQuod(newTargetPrecise, newTargetQuod);
        memcpy(global.mainChainTarget, newTargetQuod, sizeof(newTargetQuod));
    }
    printf("=============\n");
}

static void update_target() {
    // e.g. Retarget after block 2015 is made, i.e. adjusting target for
    // the incoming 2016 block
    bool shouldRetarget =
        (global.mainChainHeight + 1) % parameters.retargetPeriod == 0;
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
