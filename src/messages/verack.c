#include <string.h>

#include "messages/verack.h"
#include "messages/header.h"
#include "messages/common.h"

uint64_t serialize_verack_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    return serialize_header_only_message(ptrMessage, ptrBuffer);
}

int32_t make_verack_message(Message *ptrMessage) {
    return make_header_only_message(
        ptrMessage,
        CMD_VERACK,
        sizeof(CMD_VERACK)
    );
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
