#include <stdlib.h>

#include "messages/shared.h"
#include "blockreq.h"
#include "util.h"

uint64_t serialize_blockreq_payload(
    BlockRequestPayload *ptrPayload,
    Byte *ptrBuffer
) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(ptrPayload->version, p);
    p += serialize_to_varint(ptrPayload->hashCount, p);
    for (uint32_t i = 0; i < ptrPayload->hashCount; i++) {
        p += SERIALIZE_TO(ptrPayload->blockLocatorHash[i], p);
    }
    p += SERIALIZE_TO(ptrPayload->hashStop, p);
    return p - ptrBuffer;
}

uint64_t parse_blockreq_payload(
    Byte *ptrBuffer,
    BlockRequestPayload *ptrPayload
) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrPayload->version);
    p += parse_varint(p, &ptrPayload->hashCount);
    for (uint32_t i = 0; i < ptrPayload->hashCount; i++) {
        p += PARSE_INTO(p, &ptrPayload->blockLocatorHash[i]);
    }
    p += PARSE_INTO(p, ptrPayload->hashStop);
    return p - ptrBuffer;
}

int32_t make_blockreq_message(
    Message *ptrMessage,
    BlockRequestPayload *ptrPayload,
    char *command,
    uint8_t commandSize
) {
    ptrMessage->header.magic = mainnet.magic;
    memcpy(ptrMessage->header.command, command, commandSize);

    ptrMessage->ptrPayload = malloc(sizeof(BlockRequestPayload)); // make_message:payload
    memcpy(ptrMessage->ptrPayload, ptrPayload, sizeof(BlockRequestPayload));

    Byte buffer[MESSAGE_BUFFER_LENGTH] = {0};
    uint64_t payloadLength = serialize_blockreq_payload(ptrPayload, buffer);
    ptrMessage->header.length = (uint32_t)payloadLength;
    calculate_data_checksum(
        &buffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_blockreq_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_blockreq_payload(
        (BlockRequestPayload *) ptrMessage->ptrPayload,
        ptrBuffer + messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

uint64_t load_blockreq_message(char *path, Message *ptrMessage) {
    FILE *file = fopen(path, "rb");

    fread(ptrMessage, sizeof(ptrMessage->header), 1, file);

    uint64_t payloadLength = ptrMessage->header.length;
    Byte *buffer = malloc(payloadLength); // load_blockreq_message:buffer
    fread(buffer, payloadLength, 1, file);

    ptrMessage->ptrPayload = malloc(sizeof(BlockRequestPayload)); // load_blockreq_message:payload
    parse_blockreq_payload(buffer, ptrMessage->ptrPayload);
    fclose(file);
    free(buffer); // load_blockreq_message:buffer

    return sizeof(ptrMessage->header)+payloadLength;
}
