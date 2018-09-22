#include <stdint.h>
#include <stdlib.h>
#include "shared.h"
#include "util.h"
#include "block.h"

uint8_t calc_number_varint_width(uint64_t number) {
    if (number < VAR_INT_CHECKPOINT_8) {
        return 1;
    }
    else if (number <= VAR_INT_CHECKPOINT_16) {
        return 3;
    }
    else if (number <= VAR_INT_CHECKPIONT_32) {
        return 5;
    }
    else {
        return 9;
    }
}

uint8_t serialize_to_varint(
    uint64_t data,
    uint8_t *ptrBuffer
) {
    if (data < VAR_INT_CHECKPOINT_8) {
        ptrBuffer[0] = (uint8_t)data;
        return 1;
    }
    else if (data <= VAR_INT_CHECKPOINT_16) {
        ptrBuffer[0] = VAR_INT_PREFIX_16;
        memcpy(ptrBuffer+1, &data, 2);
        return 3;
    }
    else if (data <= VAR_INT_CHECKPIONT_32) {
        ptrBuffer[0] = VAR_INT_PREFIX_32;
        memcpy(ptrBuffer+1, &data, 4);
        return 5;
    }
    else {
        ptrBuffer[0] = VAR_INT_PREFIX_64;
        memcpy(ptrBuffer+1, &data, 8);
        return 9;
    }
}

uint8_t parse_varint(
    uint8_t *ptrBuffer,
    uint64_t *result
) {
    uint8_t firstByte = ptrBuffer[0];
    switch (firstByte) {
        case VAR_INT_PREFIX_16: {
            *result = combine_uint16(ptrBuffer+1);
            return 3;
        }
        case VAR_INT_PREFIX_32: {
            *result = combine_uint32(ptrBuffer+1);
            return 5;
        }
        case VAR_INT_PREFIX_64: {
            *result = combine_uint64(ptrBuffer+1);
            return 9;
        }
        default: {
            *result = firstByte;
            return 1;
        }
    }
}

uint64_t serialize_varstr(
    struct VariableLengthString *ptrVarStr,
    uint8_t *ptrBuffer
) {
    uint8_t varintLength = serialize_to_varint(ptrVarStr->length, ptrBuffer);
    memcpy(ptrBuffer+varintLength, ptrVarStr->string, ptrVarStr->length);
    return varintLength + ptrVarStr->length;
}

uint64_t parse_as_varstr(
    uint8_t *ptrBuffer,
    struct VariableLengthString *ptrResult
) {
    uint64_t strLength = 0;
    uint8_t lengthWidth = parse_varint(ptrBuffer, &strLength);
    ptrResult->length = strLength;
    const uint8_t markerWidth = sizeof(uint8_t);
    memcpy(ptrResult->string, ptrBuffer + markerWidth, strLength);
    return lengthWidth + strLength;
}


uint64_t serialize_network_address(
    struct NetworkAddress *ptrAddress,
    uint8_t *ptrBuffer
) {
    uint8_t *p = ptrBuffer;
    p += SERIALIZE_TO(ptrAddress->services, p);
    p += SERIALIZE_TO(ptrAddress->ip, p);
    p += SERIALIZE_TO(ptrAddress->port, p);
    return p - ptrBuffer;
}

uint64_t parse_network_address(
    uint8_t *ptrBuffer,
    struct NetworkAddress *ptrAddress
) {
    uint8_t *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrAddress->services);
    p += PARSE_INTO(p, &ptrAddress->ip);
    p += PARSE_INTO(p, &ptrAddress->port);
    return p - ptrBuffer;
}

bool starts_with_magic(void *p) {
    return combine_uint32(p) == mainnet.magic;
}

Message get_empty_message() {
    Message message = {
        .header = get_empty_header(),
        .ptrPayload = NULL,
    };
    return message;
}

uint64_t load_file(char *path, Byte *buffer) {
    FILE *file = fopen(path, "rb");
    int64_t filesize = getFileSize(file);
    fread(buffer, (size_t)filesize, 1, file);
    fclose(file);
    return (uint64_t) filesize;
}


void free_message_payload(Message *message) {
    if (is_block(message)) {
        release_block(message->ptrPayload);
        return;
    }
    FREE(message->ptrPayload, "parse_message:payload");
}
