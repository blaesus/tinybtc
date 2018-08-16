#include <string.h>

#include "verack.h"
#include "header.h"

uint64_t serialize_verack_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    const uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    return messageHeaderSize + ptrMessage->header.length;
}

int32_t make_verack_message(Message *ptrMessage) {
    ptrMessage->header.magic = parameters.magic;
    memcpy(ptrMessage->header.command, CMD_VERACK, sizeof(CMD_VERACK));
    ptrMessage->header.length = 0;
    calculate_payload_checksum(
        ptrMessage->payload,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

int32_t parse_into_verack_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    make_verack_message(ptrMessage);
    return 0;
}

void print_verack_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    printf("(verack payload is empty by definition)\n");
}
