#include <stdint.h>
#include "messages/shared.h"
#include "messages/common.h"

int32_t make_getaddr_message(Message *ptrMessage) {
    return make_header_only_message(
        ptrMessage,
        CMD_GETADDR,
        sizeof(CMD_GETADDR)
    );
}

uint64_t serialize_getaddr_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    return serialize_header_only_message(ptrMessage, ptrBuffer);
}
