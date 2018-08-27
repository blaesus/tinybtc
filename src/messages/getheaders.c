#include <stdlib.h>

#include "messages/shared.h"
#include "getheaders.h"
#include "util.h"

uint64_t serialize_getheaders_payload(
    GetheadersPayload *ptrPayload,
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

uint64_t parse_getheaders_payload(
    Byte *ptrBuffer,
    GetheadersPayload *ptrPayload
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

int32_t make_getheaders_message(
    Message *ptrMessage,
    GetheadersPayload *ptrPayload
) {
    ptrMessage->header.magic = mainnet.magic;
    memcpy(ptrMessage->header.command, CMD_GETHEADERS, sizeof(CMD_GETHEADERS));

    ptrMessage->ptrPayload = malloc(sizeof(GetheadersPayload));
    memcpy(ptrMessage->ptrPayload, ptrPayload, sizeof(GetheadersPayload));

    Byte buffer[MAX_MESSAGE_LENGTH] = {0};
    uint64_t payloadLength = serialize_getheaders_payload(ptrPayload, buffer);
    ptrMessage->header.length = (uint32_t)payloadLength;
    calculate_data_checksum(
        &buffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_getheader_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_getheaders_payload(
        (GetheadersPayload *)ptrMessage->ptrPayload,
        ptrBuffer + messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

uint64_t load_getheaders_message(
    char *path,
    Message *ptrMessage
) {
    FILE *file = fopen(path, "rb");

    fread(ptrMessage, sizeof(ptrMessage->header), 1, file);

    uint64_t payloadLength = ptrMessage->header.length;
    Byte *buffer = malloc(payloadLength);
    fread(buffer, payloadLength, 1, file);

    ptrMessage->ptrPayload = malloc(sizeof(GetheadersPayload));
    parse_getheaders_payload(buffer, ptrMessage->ptrPayload);
    fclose(file);

    return sizeof(ptrMessage->header)+payloadLength;
}
