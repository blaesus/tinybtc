#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "tx.h"
#include "util.h"

static uint64_t parse_outpoint(Byte *ptrBuffer, Outpoint *ptrOutpoint) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrOutpoint->hash);
    p += PARSE_INTO(p, &ptrOutpoint->index);
    return p - ptrBuffer;
}

static uint64_t serialize_outpoint(
    Outpoint *ptrOutpoint,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(ptrOutpoint->hash, p);
    p += SERIALIZE_TO(ptrOutpoint->index, p);
    return p - ptrBuffer;
}

static uint64_t serialize_tx_in(
    TxIn *ptrTxIn,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += serialize_outpoint(&ptrTxIn->previous_output, p);
    p += serialize_to_varint(ptrTxIn->signature_script_length, p);
    p += SERIALIZE_TO_OF_LENGTH(ptrTxIn->signature_script, p, ptrTxIn->signature_script_length);
    p += SERIALIZE_TO(ptrTxIn->sequence, p);
    return p - ptrBuffer;
}

static uint64_t serialize_tx_out(
    TxOut *ptrTxOut,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(ptrTxOut->value, p);
    p += serialize_to_varint(ptrTxOut->public_key_script_length, p);
    p += SERIALIZE_TO_OF_LENGTH(ptrTxOut->public_key_script, p, ptrTxOut->public_key_script_length);
    return p - ptrBuffer;
}

static uint64_t serialize_tx_witness(
    TxWitness *ptrTxWitness,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += serialize_to_varint(ptrTxWitness->length, p);
    p += SERIALIZE_TO_OF_LENGTH(ptrTxWitness->data, p, ptrTxWitness->length);
    return p - ptrBuffer;
}

uint64_t serialize_tx_payload(
    TxPayload *ptrPayload,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(ptrPayload->version, p);

    bool hasWitnessData = (ptrPayload->marker == WITNESS_MARKER) && (ptrPayload->flag == WITNESS_FLAG);
    if (hasWitnessData) {
        p += SERIALIZE_TO(ptrPayload->marker, p);
        p += SERIALIZE_TO(ptrPayload->flag, p);
    }

    p += serialize_to_varint(ptrPayload->txInputCount, p);
    for (uint64_t i = 0; i < ptrPayload->txInputCount; i++) {
        p += serialize_tx_in(&ptrPayload->txInputs[i], p);
    }

    p += serialize_to_varint(ptrPayload->txOutputCount, p);
    for (uint64_t i = 0; i < ptrPayload->txOutputCount; i++) {
        p += serialize_tx_out(&ptrPayload->txOutputs[i], p);
    }

    if (hasWitnessData) {
        for (uint64_t i = 0; i < ptrPayload->txInputCount; i++) {
            p += serialize_tx_witness(&ptrPayload->txWitnesses[i], p);
        }
    }
    p += SERIALIZE_TO(ptrPayload->lockTime, p);
    return p - ptrBuffer;
}

static uint64_t parse_tx_in(
    Byte *ptrBuffer,
    TxIn *ptrTxIn
) {
    Byte *p = ptrBuffer;
    p += parse_outpoint(p, &ptrTxIn->previous_output);
    p += parse_varint(p, &ptrTxIn->signature_script_length);
    p += PARSE_INTO_OF_LENGTH(p, &ptrTxIn->signature_script, ptrTxIn->signature_script_length);
    p += PARSE_INTO(p, &ptrTxIn->sequence);
    return p - ptrBuffer;
}

static uint64_t parse_tx_out(
    Byte *ptrBuffer,
    TxOut *ptrTxOut
) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrTxOut->value);
    p += parse_varint(p, &ptrTxOut->public_key_script_length);
    p += PARSE_INTO_OF_LENGTH(p, &ptrTxOut->public_key_script, ptrTxOut->public_key_script_length);
    return p - ptrBuffer;
}

static uint64_t parse_tx_witness(
    Byte *ptrBuffer,
    TxWitness *ptrTxWitness
) {
    Byte *p = ptrBuffer;
    p += parse_varint(p, &ptrTxWitness->length);
    p += PARSE_INTO_OF_LENGTH(p, &ptrTxWitness->data, ptrTxWitness->length);
    return p - ptrBuffer;
}

uint64_t parse_into_tx_payload(Byte *ptrBuffer, TxPayload *ptrTx) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrTx->version);

    Byte possibleMarker = 0;
    Byte possibleFlag = 0;
    memcpy(&possibleMarker, p, sizeof(ptrTx->marker));
    memcpy(&possibleFlag, p + sizeof(ptrTx->marker), sizeof(ptrTx->flag));
    bool hasWitness = (possibleMarker == WITNESS_MARKER) && (possibleFlag == WITNESS_FLAG);
    if (hasWitness) {
        PARSE_INTO(p, &ptrTx->marker);
        PARSE_INTO(p, &ptrTx->flag);
    }

    p += parse_varint(p, &ptrTx->txInputCount);
    for (uint64_t i = 0; i < ptrTx->txInputCount; i++) {
        p += parse_tx_in(p, &ptrTx->txInputs[i]);
    }

    p += parse_varint(p, &ptrTx->txOutputCount);
    for (uint64_t i = 0; i < ptrTx->txOutputCount; i++) {
        p += parse_tx_out(p, &ptrTx->txOutputs[i]);
    }

    if (hasWitness) {
        for (uint64_t i = 0; i < ptrTx->txInputCount; i++) {
            p += parse_tx_witness(p, &ptrTx->txWitnesses[i]);
        }
    }
    p += PARSE_INTO(p, &ptrTx->lockTime);
    return p - ptrBuffer;
}

int32_t make_tx_message(
    Message *ptrMessage,
    TxPayload *ptrPayload
) {
    ptrMessage->header.magic = mainnet.magic;
    memcpy(ptrMessage->header.command, CMD_TX, sizeof(CMD_TX));

    ptrMessage->ptrPayload = MALLOC(sizeof(TxPayload), "make_message:payload");
    memcpy(ptrMessage->ptrPayload, ptrPayload, sizeof(TxPayload));

    Byte buffer[MESSAGE_BUFFER_LENGTH] = {0};
    uint64_t payloadLength = serialize_tx_payload(ptrPayload, buffer);
    ptrMessage->header.length = (uint32_t)payloadLength;
    calculate_data_checksum(
        &buffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_tx_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_tx_payload(
        (TxPayload *)ptrMessage->ptrPayload,
        ptrBuffer+messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

// Merkle root computation
// @see https://en.bitcoin.it/wiki/Block_hashing_algorithm

void hash_tx(TxPayload *ptrTx, SHA256_HASH result) {
    Byte buffer[MESSAGE_BUFFER_LENGTH] = {0};
    uint64_t txWidth = serialize_tx_payload(ptrTx, buffer);
    dsha256(buffer, (uint32_t) txWidth, result);
}

struct HashNode {
    SHA256_HASH hash;
    struct HashNode *next;
};

typedef struct HashNode HashNode;

// @see https://en.bitcoin.it/wiki/Getblocktemplate#How_to_build_merkle_root

int32_t compute_merkle_root(TxNode *ptrFirstTxNode, SHA256_HASH result) {
    if (!ptrFirstTxNode) {
        return -1;
    }

    // Hash the linked tx list
    HashNode *ptrFirstHashNode = NULL;
    HashNode *ptrPreviousHashNode = NULL;
    TxNode *ptrTxNode = ptrFirstTxNode;
    while (ptrTxNode) {
        HashNode *newHashNode = CALLOC(1, sizeof(HashNode), "compute_merkle_root:HashNode");
        hash_tx(&ptrTxNode->tx, newHashNode->hash);
        if (!ptrFirstHashNode) {
            ptrFirstHashNode = newHashNode;
        }
        if (ptrPreviousHashNode) {
            ptrPreviousHashNode->next = newHashNode;
        }
        ptrPreviousHashNode = newHashNode;
        ptrTxNode = ptrTxNode->next;
    }

    while (ptrFirstHashNode->next) {
        HashNode *p = ptrFirstHashNode;
        while (p) {
            Byte *leftHash = p->hash;
            Byte *rightHash = p->next ? p->next->hash : p->hash;
            Byte buffer[SHA256_LENGTH * 2] = {0};
            memcpy(buffer, leftHash, SHA256_LENGTH);
            memcpy(buffer+SHA256_LENGTH, rightHash, SHA256_LENGTH);
            dsha256(buffer, SHA256_LENGTH * 2, p->hash);
            if (p->next) {
                HashNode *freeTarget = p->next;
                p->next = p->next->next;
                p = p->next;
                FREE(freeTarget, "compute_merkle_root:HashNode");
            }
            else {
                p = NULL;
            }
        }
    }
    memcpy(result, ptrFirstHashNode->hash, SHA256_LENGTH);

    FREE(ptrFirstHashNode, "compute_merkle_root:HashNode");
    return 0;
}

void print_tx_payload(TxPayload *ptrTx) {
    printf(
        "[tx]version=%u; %llu TxIns; %llu TxOuts.",
        ptrTx->version,
        ptrTx->txInputCount,
        ptrTx->txOutputCount
    );
}

bool is_outpoint_empty(Outpoint *ptrOutpoint) {
    return (ptrOutpoint->index == UINT32_MAX) && is_hash_empty(ptrOutpoint->hash);
}

bool is_coinbase(TxPayload *ptrTx) {
    return ptrTx->txInputCount == 1 && is_outpoint_empty(&ptrTx->txInputs[0].previous_output);
}

bool is_tx_legal(TxPayload *ptrTx) {
    bool nonemptyIn = ptrTx->txInputCount > 0;
    bool nonemptyOut = ptrTx->txOutputCount > 0;

    bool outpusLegal = true;
    for (uint64_t i = 0; i < ptrTx->txOutputCount; i++) {
        TxOut out = ptrTx->txOutputs[i];
        if (out.value < 0) {
            outpusLegal = false;
            break;
        }
    }

    bool inputsLegal = true;
    if (is_coinbase(ptrTx)) {
        TxIn firstIn = ptrTx->txInputs[0];
        inputsLegal = firstIn.signature_script_length <= mainnet.scriptSigSizeUpper
                      && firstIn.signature_script_length >= mainnet.scriptSigSizeLower;
    }
    else {
        for (uint64_t i = 0; i < ptrTx->txInputCount; i++) {
            TxIn in = ptrTx->txInputs[i];
            if (is_outpoint_empty(&in.previous_output)) {
                inputsLegal = false;
                break;
            }
        }
    }

    return nonemptyIn
           && nonemptyOut
           && outpusLegal
           && inputsLegal;
}
