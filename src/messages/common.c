#include <stdint.h>
#include <messages/shared.h>

int32_t make_header_only_message(
    Message *ptrMessage,
    char* command,
    uint16_t commandLength
) {
    ptrMessage->header.magic = parameters.magic;
    memcpy(ptrMessage->header.command, command, commandLength);
    ptrMessage->header.length = 0;
    calculate_payload_checksum(
        ptrMessage->payload,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_header_only_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    const uint64_t messageHeaderSize = sizeof(ptrMessage->header);
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    return messageHeaderSize + ptrMessage->header.length;
}
