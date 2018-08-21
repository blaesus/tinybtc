#include <stdint.h>
#include <stdlib.h>

#include "messages/block.h"
#include "util.h"

uint64_t serialize_block_payload_header(
    BlockPayloadHeader *ptrHeader,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;

    memcpy(p, &ptrHeader->version, sizeof(ptrHeader->version));
    p += sizeof(ptrHeader->version);

    memcpy(p, &ptrHeader->prev_block, sizeof(ptrHeader->prev_block));
    p += sizeof(ptrHeader->prev_block);

    memcpy(p, &ptrHeader->merkle_root, sizeof(ptrHeader->merkle_root));
    p += sizeof(ptrHeader->merkle_root);

    memcpy(p, &ptrHeader->timestamp, sizeof(ptrHeader->timestamp));
    p += sizeof(ptrHeader->timestamp);

    memcpy(p, &ptrHeader->bits, sizeof(ptrHeader->bits));
    p += sizeof(ptrHeader->bits);

    memcpy(p, &ptrHeader->nonce, sizeof(ptrHeader->nonce));
    p += sizeof(ptrHeader->nonce);

    return p - ptrBuffer;
}

int32_t parse_into_block_payload(
    Byte *ptrBuffer,
    BlockPayload *ptrBlock
) {
    Byte *p = ptrBuffer;

    p += PARSE_INTO(p, &ptrBlock->header);
    p += parse_varint(p, &ptrBlock->txCount);

    TxNode *ptrPreviousNode = NULL;
    for (uint64_t i = 0; i < ptrBlock->txCount; i++) {
        TxNode *ptrNewNode = calloc(1, sizeof(TxNode));
        p += parse_tx_payload(p, &ptrNewNode->tx);
        if (!ptrBlock->ptrFirstTxNode) {
            ptrBlock->ptrFirstTxNode = ptrNewNode;
        }
        if (ptrPreviousNode) {
            ptrPreviousNode->next = ptrNewNode;
        }
        ptrPreviousNode = ptrNewNode;
    }
    return 0;
}

uint64_t serialize_block_payload(
    BlockPayload *ptrPayload,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;

    BlockPayloadHeader *ptrHeader = &ptrPayload->header;

    p += serialize_block_payload_header(ptrHeader, p);
    p += serialize_to_varint(ptrPayload->txCount, p);

    TxNode *txNode = ptrPayload->ptrFirstTxNode;
    for (uint64_t i = 0; i < ptrPayload->txCount; i++) {
        p += serialize_tx_payload(&txNode->tx, p);
        txNode = txNode->next;
    }

    return p - ptrBuffer;
}

int32_t make_block_message(
    Message *ptrMessage,
    BlockPayload *ptrPayload
) {
    ptrMessage->header.magic = parameters.magic;
    memcpy(ptrMessage->header.command, CMD_BLOCK, sizeof(CMD_BLOCK));

    ptrMessage->ptrPayload = malloc(sizeof(BlockPayload));
    memcpy(ptrMessage->ptrPayload, ptrPayload, sizeof(BlockPayload));

    Byte buffer[MAX_MESSAGE_LENGTH] = {0};
    uint64_t payloadLength = serialize_block_payload(ptrPayload, buffer);
    calculate_data_checksum(
        &buffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    ptrMessage->header.length = (uint32_t)payloadLength;
    return 0;
}

uint64_t serialize_block_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_block_payload(
        (BlockPayload *)ptrMessage->ptrPayload,
        ptrBuffer+messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

void load_block_message(
    char *path,
    Message *ptrMessage
) {
    FILE *file = fopen(path, "rb");

    fread(ptrMessage, sizeof(ptrMessage->header), 1, file);

    uint64_t payloadLength = ptrMessage->header.length;
    Byte *buffer = calloc(1, payloadLength);
    fread(buffer, payloadLength, 1, file);

    ptrMessage->ptrPayload = calloc(1, sizeof(BlockPayload));
    parse_into_block_payload(buffer, ptrMessage->ptrPayload);
    fclose(file);
}
