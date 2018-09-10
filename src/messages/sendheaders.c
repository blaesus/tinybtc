#include "messages/sendheaders.h"
#include "messages/common.h"

int32_t make_sendheaders_message(
    Message *ptrMessage
) {
    return make_header_only_message(
        ptrMessage,
        CMD_SENDHEADERS,
        sizeof(CMD_SENDHEADERS)
    );
}

uint64_t serialize_sendheaders_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    return serialize_header_only_message(ptrMessage, ptrBuffer);
}
