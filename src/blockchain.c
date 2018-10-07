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
#include "utils/integers.h"


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

int8_t search_utxo(Outpoint *outpoint, TxPayload *txs, uint64_t txLimit, TxOut *sourceOutput) {
    if (global.mode == MODE_VALIDATE_ONE) {
        TxPayload *tx = CALLOC(1, sizeof(*tx), "search_utxo:tx");
        int8_t status = load_tx(outpoint->txHash, tx);
        if (status == 0 && outpoint->index < tx->txOutputCount) {
            memcpy(sourceOutput, &tx->txOutputs[outpoint->index], sizeof(TxOut));
            FREE(tx, "search_utxo:tx");
            return 0;
        }
        else {
            FREE(tx, "search_utxo:tx");
            return -1;
        }
    }
    // Coinbase
    if (is_outpoint_empty(outpoint)) {
        return -30;
    }
    int8_t status = load_utxo(outpoint, sourceOutput);
    if (!status) {
        return 0;
    }
    // Search in the same block
    for (uint64_t txIndex = 0; txIndex < txLimit; txIndex++) {
        TxPayload *candidateSource = &txs[txIndex];
        SHA256_HASH txHash;
        hash_tx(candidateSource, txHash);
        if (sha256_match(txHash, outpoint->txHash) && candidateSource->txOutputCount > outpoint->index) {
            memcpy(sourceOutput, &candidateSource->txOutputs[outpoint->index], sizeof(*sourceOutput));
            return 0;
        }
    }
    return -1;
}

uint64_t sum_outputs_from_tx(TxPayload *tx) {
    uint64_t sum = 0;
    for (uint64_t outputIndex = 0; outputIndex < tx->txOutputCount; outputIndex++) {
        TxOut *output = &tx->txOutputs[outputIndex];
        sum += output->value;
    }
    return sum;
}

uint64_t sum_inputs_from_tx(TxPayload *tx, TxPayload *txs, uint64_t txLimit) {
    uint64_t sum = 0;
    TxOut *sourceOutput = CALLOC(1, sizeof(*sourceOutput), "sum_inputs_from_tx:sourceOutput");
    for (uint64_t inputIndex = 0; inputIndex < tx->txInputCount; inputIndex++) {
        TxIn *input = &tx->txInputs[inputIndex];
        if (is_coinbase(input)) {
            continue;
        }
        memset(sourceOutput, 0, sizeof(*sourceOutput));
        int8_t error = search_utxo(&input->previous_output, txs, txLimit, sourceOutput);
        if (error) {
            fprintf(
                stderr,
                "search_utxo error %i: searching %s #%u\n",
                error,
                binary_to_hexstr(input->previous_output.txHash, SHA256_LENGTH),
                input->previous_output.index
            );
        }
        else {
            sum += sourceOutput->value;
        }
    }
    FREE(sourceOutput, "sum_inputs_from_tx:sourceOutput");
    return sum;
}
uint64_t compute_tx_residue(TxPayload *tx, TxPayload *txs, uint64_t txLimit) {
    uint64_t input = sum_inputs_from_tx(tx, txs, txLimit);
    uint64_t output = sum_outputs_from_tx(tx);
    return input - output;
}

uint64_t agregate_residues(TxPayload *txs, uint64_t count, uint64_t initialOffset) {
    uint64_t sum = 0;
    for (uint64_t txIndex = initialOffset; txIndex < count; txIndex++) {
        TxPayload *tx = &txs[txIndex];
        sum += compute_tx_residue(tx, txs, txIndex);
    }
    return sum;
}

bool is_normal_tx_valid(uint64_t txIndex, TxPayload *txs) {
    TxPayload *tx = &txs[txIndex];

    bool amountValid = false;
    if (txIndex == 0) {
        amountValid = true; // Handled at is_initial_tx_valid()
    }
    else {
        uint64_t totalInputAmount = sum_inputs_from_tx(tx, txs, txIndex);
        uint64_t totalOutputAmount = sum_outputs_from_tx(tx);
        amountValid = totalInputAmount >= totalOutputAmount;
    }

    bool signaturesValid = true;
    TxOut *sourceOutput = CALLOC(1, sizeof(TxOut), "is_tx_valid:txSource");
    for (uint32_t inputIndex = 0; inputIndex < tx->txInputCount; inputIndex++) {
        TxIn *input = &tx->txInputs[inputIndex];
        if (is_coinbase(input)) {
            continue;
        }

        memset(sourceOutput, 0, sizeof(*sourceOutput));
        Outpoint *outpoint = &input->previous_output;
        int8_t error = search_utxo(outpoint, txs, txIndex, sourceOutput);
        if (error) {
            fprintf(stderr, "Cannot load source tx output (%i)...\n", error);
            signaturesValid = false;
            break;
        }

        uint64_t programLength = input->signature_script_length + 1 + sourceOutput->public_key_script_length;

        Byte *program = CALLOC(1, programLength, "is_tx_valid:program");
        memcpy(program, input->signature_script, input->signature_script_length);
        Byte codeSeparator = OP_CODESEPARATOR;
        memcpy(program+input->signature_script_length, &codeSeparator, 1);
        memcpy(program+input->signature_script_length+1, sourceOutput->public_key_script, sourceOutput->public_key_script_length);
        CheckSigMeta meta = {
            .sourceOutput = sourceOutput,
            .txInputIndex = inputIndex,
            .currentTx = tx,
        };
        bool scriptWorks = run_program(program, programLength, meta);
        FREE(program, "is_tx_valid:program");
        if (!scriptWorks) {
            signaturesValid = false;
            break;
        }
    }
    FREE(sourceOutput, "is_tx_valid:txSource");

    bool result = amountValid && signaturesValid;

    return result;
}

bool is_initial_tx_valid(uint64_t txIndex, TxPayload *txs, BlockPayload *block, BlockIndex *blockIndex) {
    bool validAsNormalTx = is_normal_tx_valid(txIndex, txs);

    bool amountValid;
    uint64_t totalInputAmount = sum_inputs_from_tx(&txs[txIndex], txs, 0);
    uint64_t totalOutputAmount = sum_outputs_from_tx(&txs[txIndex]);
    uint64_t transactionFees = agregate_residues(block->txs, block->txCount, 1);
    int64_t coinbaseSubsidy = COIN(50) >> (blockIndex->context.height / 210000);
    amountValid = totalInputAmount + coinbaseSubsidy + transactionFees >= totalOutputAmount;

    return validAsNormalTx && amountValid;
}


bool is_tx_valid(uint64_t txIndex, TxPayload *txs, BlockPayload *block, BlockIndex *blockIndex) {
    TxPayload *tx = &txs[txIndex];
    #if LOG_VALIDATION_PROCEDURES
    printf("\nValidating TX #%llu\n", txIndex);
    #endif
    if (!is_tx_legal(tx)) {
        return false;
    }
    bool firstTxInBlock = txIndex == 0;
    if (firstTxInBlock) {
        return is_initial_tx_valid(txIndex, txs, block, blockIndex);
    }
    else {
        return is_normal_tx_valid(txIndex, txs);
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
        if (!is_tx_valid(i, ptrCandidate->txs, ptrCandidate, ptrIndex)) {
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

void register_validated_block(BlockPayload *ptrBlock) {
    SHA256_HASH blockHash = {0};
    hash_block_header(&ptrBlock->header, blockHash);
    print_hash_with_description("Registering block ", blockHash);
    SHA256_HASH txHash = {0};
    for (uint64_t txIndex = 0; txIndex < ptrBlock->txCount; txIndex++) {
        TxPayload *tx = &ptrBlock->txs[txIndex];
        hash_tx(tx, txHash);
        for (uint64_t outIndex = 0; outIndex < tx->txOutputCount; outIndex++) {
            TxOut *out = &tx->txOutputs[outIndex];
            Outpoint outpoint;
            outpoint.index = (uint32_t)outIndex;
            memcpy(outpoint.txHash, txHash, SHA256_LENGTH);
            int8_t status = save_utxo(&outpoint, out);
            if (status) {
                #if LOG_BLOCK_REGISTRATION_DETAILS
                fprintf(stderr, "register utxo: %i\n", status);
                #endif
            }
            else  {
                #if LOG_BLOCK_REGISTRATION_DETAILS
                printf("registered utxo: %s %llu\n", binary_to_hexstr(txHash, SHA256_LENGTH), outIndex);
                #endif
            }
        }
        for (uint64_t inIndex = 0; inIndex < tx->txInputCount; inIndex++) {
            TxIn *input = &tx->txInputs[inIndex];
            if (!is_coinbase(input)) {
                spend_output(&input->previous_output);
                #if LOG_BLOCK_REGISTRATION_DETAILS
                printf(
                    "spent utxo: %s %u\n",
                    binary_to_hexstr(input->previous_output.txHash, SHA256_LENGTH),
                    input->previous_output.index
                );
                #endif
            }
        }
    }
}

int8_t process_incoming_block(BlockPayload *ptrBlock, bool persistent) {
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

    if (persistent) {
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
                register_validated_block(ptrBlock);
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

double scan_block_indices(bool recheckBlockExistence, bool reloadBlockContent) {
    printf("Scanning block indices...\n");
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
        if (recheckBlockExistence) {
            ptrIndex->meta.fullBlockAvailable = is_block_downloaded(ptrIndex->meta.hash);
        }
        if (ptrIndex->meta.fullBlockAvailable) {
            fullBlockAvailable++;
            if (reloadBlockContent) {
                BlockPayload *block = CALLOC(1, sizeof(*block), "scan_block_indices:block");
                int8_t error = load_block(ptrIndex->meta.hash, block);
                if (error == 0) {
                    process_incoming_block(block, true);
                }
                FREE(block, "scan_block_indices:block");
            }
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

// 2: valid and continue; 1: valid and stop; 0: invalid; <0: error

int8_t validate_block(Byte *target, bool saveValidation, Byte *nextHash) {
    BlockIndex *index = GET_BLOCK_INDEX(target);
    if (!index) {
        fprintf(stderr, "validate_blocks: No index for current target\n");
        return -1;
    }
    else if (!index->meta.fullBlockAvailable) {
        fprintf(stderr, "validate_blocks: block %s not available\n", binary_to_hexstr(target, SHA256_LENGTH));
        return -10;
    }
    printf(
        "\nValidating block %u %s",
        index->context.height,
        binary_to_hexstr(index->meta.hash, SHA256_LENGTH)
    );
    BlockPayload *block = CALLOC(1, sizeof(*block), "validate_blocks:block");
    int8_t blockLoadStatus = load_block(index->meta.hash, block);
    #if LOG_VALIDATION_PROCEDURES
    print_block_payload(block);
    #endif

    int8_t blockValidation = 0;

    if (blockLoadStatus) {
        fprintf(stderr, "validate_blocks: Cannot load block\n");
        blockValidation = -10;
        goto release;
    }

    bool hasChild = index->context.children.length > 0;

    bool blockValid = is_block_valid(block, index);
    if (!blockValid) {
        fprintf(stderr, "validate_blocks: Block invalid\n");
        blockValidation = 0;
        goto release;
    }
    else {
        if (hasChild) {
            blockValidation = 2;
        }
        else {
            blockValidation = 1;
        }
    }

    printf(" [validated]\n");

    if (saveValidation) {
        index->meta.fullBlockValidated = true;
        global.mainValidatedTip = *index;
        register_validated_block(block);
        index->meta.outputsRegistered = true;
    }

    if (nextHash && hasChild) {
        memcpy(nextHash, index->context.children.hashes[0], SHA256_LENGTH); // TODO: handle side-chain
    }

    release:
    release_block(block);
    return blockValidation;
}

uint32_t validate_blocks(double maxTime) {
    double start = get_now();
    double now = start;
    printf("Validating blocks for %.1fms\n", maxTime);
    SHA256_HASH blockHash = {0};
    Byte *lastValid = global.mainValidatedTip.meta.hash;
    BlockIndex *index = GET_BLOCK_INDEX(lastValid);
    if (!index) {
        return 0;
    }
    else if (index->context.children.length == 0) {
        return 1;
    }
    memcpy(blockHash, index->context.children.hashes[0], SHA256_LENGTH);
    uint32_t checkedBlocks = 0;
    double averageTime = 0.0;
    while ((now - start + averageTime) < maxTime) {
        int8_t validation = validate_block(blockHash, true, blockHash);
        checkedBlocks++;
        now = get_now();
        averageTime = (now - start) / maxTime;
        if (validation != 2) {
            break;
        }
    }
    printf("\nStopping validation after %.1fms\n", now - start);
    return checkedBlocks;
}

void reset_validation() {
    BlockIndex *index = GET_BLOCK_INDEX(global.genesisHash);
    global.mainValidatedTip = *index;
    Byte *keys = CALLOC(MAX_BLOCK_COUNT, SHA256_LENGTH, "save_block_indices:keys");
    uint32_t keyCount = (uint32_t)hashmap_getkeys(&global.blockIndices, keys);
    for (uint32_t i = 0; i < keyCount; i++) {
        Byte key[SHA256_LENGTH] = {0};
        memcpy(key, keys + i * SHA256_LENGTH, SHA256_LENGTH);
        BlockIndex *ptrIndex = GET_BLOCK_INDEX(key);
        ptrIndex->meta.fullBlockValidated = false;
        ptrIndex->meta.outputsRegistered = false;
    }
}

void reset_utxo() {
    printf("Reseting utxo\n");
    reset_validation();
    destory_db(config.utxoDBName);
    printf("Done.\n");
}

void revalidate(uint32_t maxTime) {
    uint32_t checkedBlocks = validate_blocks(maxTime);
    printf("\nChecked %u blocks\n", checkedBlocks);
}
