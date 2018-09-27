#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#include "blockchain.h"
#include "globalstate.h"
#include "hash.h"
#include "units.h"
#include "persistent.h"
#include "script.h"
#include "utils/memory.h"
#include "utils/datetime.h"
#include "utils/data.h"


static int8_t get_maximal_target(BlockIndex *index, TargetCompact *result);

double pow256(double x) {
    return pow(2, x * 8);
}

double target_compact_to_float(TargetCompact targetBytes) {
    uint32_t exponentWidth = targetBytes >> 24;
    exponentWidth -= 3;
    uint32_t mantissa =
        + ((targetBytes >> 16) & 0xff) * 65536
        + ((targetBytes >> 8) & 0xff) * 256
        + (targetBytes & 0xff);
    return mantissa * pow256(exponentWidth);
}

// Compact-Bignum conversion adapted from Bitcoin 0.0.1 by Satoshi

void target_compact_to_bignum(TargetCompact targetBytes, BIGNUM *ptrTarget) {
    uint32_t size = targetBytes >> 24;
    Byte inputBytes[64] = {0};
    inputBytes[3] = (Byte)size;
    if (size >= 1) inputBytes[4] = (Byte)((targetBytes >> 16) & 0xff);
    if (size >= 2) inputBytes[5] = (Byte)((targetBytes >> 8) & 0xff);
    if (size >= 3) inputBytes[6] = (Byte)((targetBytes >> 0) & 0xff);
    BN_mpi2bn(&inputBytes[0], 4 + size, ptrTarget);
}

uint32_t target_bignum_to_compact(BIGNUM *ptrTarget) {
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

bool is_block_header_valid(BlockIndex *index) {
    bool headerValid;
    SHA256_HASH hash = {0};
    TargetCompact maxTarget;
    int8_t targetCalculationError = get_maximal_target(index, &maxTarget);
    if (targetCalculationError) {
        return -50;
    }
    headerValid = hash_satisfies_target_compact(hash, maxTarget);
    return headerValid;
}

bool is_coinbase_tx_valid(TxPayload *tx) {
    // int64_t maxSubsidy = COIN(50) >> (blockIndex->context.height / 210000);
    // TODO: Police on max subsidy
    return tx != NULL;
}

bool is_normal_tx_valid(TxPayload *tx) {
    TxOut *output = CALLOC(1, sizeof(TxOut), "is_tx_valid:txSource");
    bool result = true;
    for (uint32_t i = 0; i < tx->txInputCount; i++) {
        TxIn *input = &tx->txInputs[i];
        memset(output, 0, sizeof(*output));
        int8_t error = load_utxo(&input->previous_output, output);
        if (error) {
            fprintf(stderr, "Cannot load source tx\n");
            result = false;
            goto release;
        }
        uint64_t programLength = input->signature_script_length + output->public_key_script_length;

        Byte *program = CALLOC(1, programLength, "is_tx_valid:program");
        memcpy(program, input->signature_script, input->signature_script_length);
        memcpy(program+input->signature_script_length, output->public_key_script, output->public_key_script_length);
        CheckSigMeta meta = {
            .sourceOutput = output,
            .txInputIndex = i,
            .currentTx = tx,
        };
        result = run_program(program, programLength, meta);
        FREE(program, "is_tx_valid:program");
        if (!result) {
            printf("verification script failed\n");
            goto release;
        }
    }
    release:
    FREE(output, "is_tx_valid:txSource");
    return result;
}

bool is_tx_valid(TxPayload *tx, BlockIndex *blockIndex) {
    if (blockIndex == NULL) {
        fprintf(stderr, "No block index\n");
        return false;
    }

    if (is_coinbase(tx)) {
        return is_coinbase_tx_valid(tx);
    }
    else {
        return is_normal_tx_valid(tx);
    }
}

static bool is_block_checkpoint_compatible(BlockIndex *ptrIndex) {
    for (uint32_t i = 0; i < MAX_CHECKPOINTS; i++) {
        struct ChainCheckPoint checkpoint = mainnet.checkpoints[i];
        if (!checkpoint.height) {
            continue;
        }
        if (checkpoint.height == ptrIndex->context.height) {
            SHA256_HASH expectedHash = {0};
            sha256_hex_to_binary(checkpoint.hashBEHex, expectedHash);
            reverse_endian(expectedHash, SHA256_LENGTH);
            if (memcmp(expectedHash, ptrIndex->meta.hash, SHA256_LENGTH) != 0) {
                return false;
            };
        }
    }
    return true;
}

bool is_block_valid(BlockPayload *ptrCandidate, BlockIndex *ptrIndex) {

    bool isBlockLegal = is_block_legal(ptrCandidate);

    bool satisfyCheckpoint = is_block_checkpoint_compatible(ptrIndex);

    bool allTxValid = true;
    for (uint64_t i = 0; i < ptrCandidate->txCount; i++) {
        if (!is_tx_valid(&ptrCandidate->txs[i], ptrIndex)) {
            allTxValid = false;
            break;
        }
    }

    bool isBlockValid = isBlockLegal && satisfyCheckpoint && allTxValid;

    return isBlockValid;
}


int8_t process_incoming_block_header(BlockPayloadHeader *ptrHeader) {
    if (!is_block_header_legal(ptrHeader)) {
        fprintf(stderr, "Received illegal header\n");
        return -2;
    }
    SHA256_HASH hash = {0};
    dsha256(ptrHeader, sizeof(BlockPayloadHeader), hash);
    BlockIndex *savedHeader = hashmap_get(&global.blockIndices, hash, NULL);
    if (savedHeader) {
        return HEADER_EXISTED;
    }

    BlockIndex index;
    memset(&index, 0, sizeof(index));

    // Header data
    memcpy(&index.header, ptrHeader, sizeof(index.header));

    // Meta
    memcpy(&index.meta.hash, hash, SHA256_LENGTH);

    // Context
    BlockIndex *parent = hashmap_get(&global.blockIndices, ptrHeader->prev_block, NULL);
    if (parent) {
        index.context.height = parent->context.height + 1;
        index.context.chainPOW = parent->context.chainPOW + calc_block_pow(index.header.target);
        switch (parent->context.chainStatus) {
            case CHAIN_STATUS_MAINCHAIN: {
                if (parent->context.children.length == 0) {
                    index.context.chainStatus = CHAIN_STATUS_MAINCHAIN;
                }
                else {
                    index.context.chainStatus = CHAIN_STATUS_SIDECHAIN;
                }
                break;
            }
            case CHAIN_STATUS_SIDECHAIN: {
                index.context.chainStatus = CHAIN_STATUS_SIDECHAIN;
                break;
            }
            case CHAIN_STATUS_ORPHAN: {
                index.context.chainStatus = CHAIN_STATUS_ORPHAN;
                break;
            }
            default: {
                fprintf(stderr, "Cannot recognize parent status of %u", parent->context.chainStatus);
            }
        }

        if (index.context.chainStatus == CHAIN_STATUS_SIDECHAIN) {
            if (global.mainHeaderTip.context.chainPOW < index.context.chainPOW) {
                printf("Side chain overtaking main chain: should reorg...\n");
            }
            // TODO: Handle reorg
        }
    }
    else {
        // We don't know new block's parent
        add_orphan(hash);
        index.context.chainPOW = calc_block_pow(index.header.target);
    }

    // Validation
    bool headerValid = is_block_header_valid(&index);
    if (!headerValid) {
        fprintf(stderr, "Invalid header\n");
        return -100;
    }

    // Update parent's context (if header is valid)
    if (parent) {
        memcpy(parent->context.children.hashes[parent->context.children.length], hash, SHA256_LENGTH);
        parent->context.children.length += 1;
    }

    bool isNewTip = index.context.chainStatus == CHAIN_STATUS_MAINCHAIN
                    && index.context.chainPOW > global.mainHeaderTip.context.chainPOW;
    if (isNewTip) {
        print_hash_with_description("Updating header tip to ", index.meta.hash);
        memcpy(&global.mainHeaderTip, &index, sizeof(index));
    }

    int8_t setError = SET_BLOCK_INDEX(hash, index);
    if (setError) {
        return -4;
    }
    return 0;
}

int8_t get_maximal_target(BlockIndex *index, TargetCompact *result) {
    *result = 0;
    if (index->context.height < mainnet.retargetPeriod) {
        *result = global.genesisBlock.header.target;
        return 0;
    }
    else if ((index->context.height % mainnet.retargetPeriod) != 0) {
        BlockIndex *parent = GET_BLOCK_INDEX(index->header.prev_block);
        if (!parent) {
            print_hash_with_description("get_maximal_target: Cannot find parent for index ", index->meta.hash);
            return -1;
        }
        *result = parent->header.target;
        return 0;
    }

    printf("\n=== Retargeting at height %u ===\n", index->context.height);
    print_hash_with_description("Retargeting from tip ", index->meta.hash);

    Byte *ptrRetargetPeriodStart = index->header.prev_block;
    for (uint32_t counter = 0; counter < mainnet.retargetLookBackPeriod; counter++) {
        BlockIndex *ptrIndex = GET_BLOCK_INDEX(ptrRetargetPeriodStart);
        if (!ptrIndex) {
            print_hash_with_description("get_maximal_target: Cannot find index", ptrRetargetPeriodStart);
            return -2;
        }
        ptrRetargetPeriodStart = ptrIndex->header.prev_block;
    }
    print_hash_with_description("Retarget period initial node tracked back to ", ptrRetargetPeriodStart);

    BlockIndex *ptrStartBlockIndex = GET_BLOCK_INDEX(ptrRetargetPeriodStart);
    BlockIndex *ptrEndBlockIndex = GET_BLOCK_INDEX(index->header.prev_block);
    uint32_t actualPeriod = ptrEndBlockIndex->header.timestamp - ptrStartBlockIndex->header.timestamp;
    printf(
        "time difference in retarget period: %u seconds (%2.1f days) [from %u, to %u]\n",
        actualPeriod,
        1.0 * actualPeriod / DAY_TO_SECOND(1),
        ptrStartBlockIndex->header.timestamp,
        ptrEndBlockIndex->header.timestamp
    );

    double ratio = (double)actualPeriod / (double)mainnet.desiredRetargetPeriod;
    double MAX_TARGET = target_compact_to_float(global.genesisBlock.header.target);
    double currentTargetFloat = target_compact_to_float(ptrEndBlockIndex->header.target);
    double nextTargetFloat = currentTargetFloat * ratio;
    if (nextTargetFloat > MAX_TARGET) {
        printf("Next target hitting ceiling, using ceiling instead\n");
        *result = global.genesisBlock.header.target;
    }
    else {
        double difficulty = MAX_TARGET / nextTargetFloat;
        printf("retarget: %.3e -> %.3e (difficulty %.2f)\n", currentTargetFloat, nextTargetFloat, difficulty);
        BIGNUM *newTarget = BN_new();
        target_compact_to_bignum(ptrEndBlockIndex->header.target, newTarget);
        if (actualPeriod > mainnet.desiredRetargetPeriod * mainnet.retargetBound) {
            BN_mul_word(newTarget, mainnet.retargetBound);
        }
        else if (actualPeriod * mainnet.retargetBound < mainnet.desiredRetargetPeriod) {
            BN_div_word(newTarget, mainnet.retargetBound);
        }
        else {
            BN_mul_word(newTarget, actualPeriod);
            BN_div_word(newTarget, mainnet.desiredRetargetPeriod);
        }
        *result = target_bignum_to_compact(newTarget);
    }
    printf("New target %u (%x)\n", *result, *result);
    printf("=============\n");
    return 0;
}

uint32_t max_full_block_height_from_genesis() {
    uint32_t height = mainnet.genesisHeight;
    SHA256_HASH hash = {0};
    memcpy(hash, global.genesisHash, SHA256_LENGTH);
    while (true) {
        BlockIndex *index = GET_BLOCK_INDEX(hash);
        if (!index || !index->meta.fullBlockAvailable) {
            return height - 1;
        }
        else if (index->context.children.length == 0) {
            return height;
        }
        else {
            // TODO: handle side-chain
            memcpy(hash, index->context.children.hashes[0], SHA256_LENGTH);
            height++;
        }
    }
}

// @see GetBlockProof() in Bitcoin Core's 'chain.cpp'

double calc_block_pow(TargetCompact targetBytes) {
    if (targetBytes == 0) {
        return 0;
    }
    double targetFloat = target_compact_to_float(targetBytes);
    return pow(2, 256) / (targetFloat + 1);
}

void register_block_outputs_as_available(BlockPayload *ptrBlock) {
    SHA256_HASH blockHash = {0};
    hash_block_header(&ptrBlock->header, blockHash);
    print_hash_with_description("Registering outputs of ", blockHash);
    SHA256_HASH txHash = {0};
    for (uint64_t i = 0; i < ptrBlock->txCount; i++) {
        TxPayload *tx = &ptrBlock->txs[i];
        hash_tx(tx, txHash);
        for (uint64_t outIndex = 0; outIndex < tx->txOutputCount; outIndex++) {
            TxOut *out = &tx->txOutputs[i];
            Outpoint outpoint;
            outpoint.index = (uint32_t)outIndex;
            memcpy(outpoint.hash, txHash, 0);
            int8_t status = save_utxo(&outpoint, out);
            if (status) {
                fprintf(stderr, "register utxo: %i\n", status);
            }
        }
    }
}

int8_t process_incoming_block(BlockPayload *ptrBlock) {
    double start = get_now();
    if (!is_block_legal(ptrBlock)) {
        fprintf(stderr, "Illegal block\n");
        return -1;
    }

    // Index
    int8_t status = process_incoming_block_header(&ptrBlock->header);
    if (status != 0 && status != HEADER_EXISTED) {
        fprintf(stderr, "header error status %i\n", status);
        return status;
    }
    SHA256_HASH hash = {0};
    dsha256(&ptrBlock->header, sizeof(ptrBlock->header), hash);

    BlockIndex *index = GET_BLOCK_INDEX(hash);
    if (!index) {
        fprintf(stderr, "process_incoming_block: cannot find block index\n");
        return -30;
    }

    if (!global.catchupMode) {
        bool valid = is_block_valid(ptrBlock, index);
        if (valid) {
            index->meta.fullBlockValidated = true;
            bool onMainchain = index->context.chainStatus == CHAIN_STATUS_MAINCHAIN;
            bool morePOW = index->context.chainPOW > global.mainValidatedTip.context.chainPOW;
            bool shouldMoveTip = onMainchain && morePOW;
            if (shouldMoveTip) {
                global.mainValidatedTip = *index;
                print_hash_with_description(
                    "Valid incoming block: move validated tip to ", index->meta.hash
                );
            }
            else {
                printf("Valid incoming block: not moving tip\n");
            }
            if (!index->meta.outputsRegistered) {
                register_block_outputs_as_available(ptrBlock);
                index->meta.outputsRegistered = true;
            }
        }
        else {
            index->meta.fullBlockValidated = false;
            fprintf(stderr, "Block invalid\n");
        }
    }

    printf("handle incoming block: %.1fms\n", get_now() - start);

    // Persistence
    int8_t saveError = save_block(ptrBlock);
    if (saveError) {
        fprintf(stderr, "save block error\n");
        return -5;
    }
    else {
        print_hash_with_description("Block saved: ", hash);
        index->meta.fullBlockAvailable = true;
    }

    for (uint64_t i = 0; i < ptrBlock->txCount; i++) {
        save_tx_location(&ptrBlock->txs[i], index->meta.hash);
    }
    return 0;
}

double verify_block_indices(bool loadBlock) {
    printf("Verifying block indices...\n");
    Byte *keys = CALLOC(MAX_BLOCK_COUNT, SHA256_LENGTH, "recalculate_block_indices:keys");
    uint32_t indexCount = (uint32_t)hashmap_getkeys(&global.blockIndices, keys);
    uint32_t fullBlockAvailable = 0;

    for (uint32_t i = 0; i < indexCount; i++) {
        if (i % 2000 == 0) {
            printf("verifying block index %u/%u\n", i, indexCount);
        }
        Byte key[SHA256_LENGTH] = {0};
        memcpy(key, keys + i * SHA256_LENGTH, SHA256_LENGTH);
        BlockIndex *ptrIndex = hashmap_get(&global.blockIndices, key, NULL);
        if (!ptrIndex) {
            printf("Key not found\n");
            continue;
        }
        dsha256(&ptrIndex->header, sizeof(BlockPayloadHeader), ptrIndex->meta.hash);
        if (loadBlock) {
            if (ptrIndex->meta.fullBlockAvailable) {
                ptrIndex->meta.fullBlockAvailable = false;
                BlockPayload *ptrBlock = CALLOC(1, sizeof(BlockPayload), "block_payload");
                int8_t status = load_block(ptrIndex->meta.hash, ptrBlock);
                if (!status) {
                    ptrIndex->meta.fullBlockAvailable = true;
                }
                release_block(ptrBlock);
            }
        }
        if (ptrIndex->meta.fullBlockAvailable) {
            fullBlockAvailable++;
        }
        if (ptrIndex->context.chainStatus == CHAIN_STATUS_ORPHAN) {
            add_orphan(ptrIndex->meta.hash);
        }
    }
    FREE(keys, "recalculate_block_indices:keys");
    printf("%u block indices; %u full blocks available; %u orphans\n", indexCount, fullBlockAvailable, global.orphanCount);
    printf("Done.\n");
    return fullBlockAvailable * 1.0 / indexCount;
}

void validate_blocks(bool fromGenesis) {
    printf("Validating blocks...\n");
    SHA256_HASH blockHash = {0};
    Byte *startingHash = fromGenesis ? global.genesisHash : global.mainValidatedTip.meta.hash;
    memcpy(blockHash, startingHash, SHA256_LENGTH);
    while (true) {
        BlockIndex *index = GET_BLOCK_INDEX(blockHash);
        print_hash_with_description("Validating ", blockHash);
        if (!index) {
            return;
        }
        if (index->context.children.length == 0) {
            return;
        }
        BlockIndex *childIndex = GET_BLOCK_INDEX(index->context.children.hashes[0]); // TODO: Handle side-chain
        if (!childIndex) {
            return;
        }
        BlockPayload *child = CALLOC(1, sizeof(*child), "validate_blocks:block");
        int8_t status = load_block(childIndex->meta.hash, child);
        bool continueScanning = false;
        if (status) {
            fprintf(stderr, "validate_blocks: Cannot load block\n");
        }
        else if (!is_block_valid(child, childIndex)) {
            fprintf(stderr, "validate_blocks: Block invalid\n");
        }
        else {
            print_hash_with_description("Block validated: ", childIndex->meta.hash);
            childIndex->meta.fullBlockValidated = true;
            global.mainValidatedTip = *childIndex;
            memcpy(blockHash, childIndex->meta.hash, SHA256_LENGTH);
            continueScanning = true;
            if (!childIndex->meta.outputsRegistered) {
                register_block_outputs_as_available(child);
                childIndex->meta.outputsRegistered = true;
            }
        }
        release_block(child);
        if (!continueScanning) {
            return;
        }
    }
}
