#pragma once

#include <stdint.h>
#include <messages/shared.h>

int32_t make_sendheaders_message(
    Message *ptrMessage
);

uint64_t serialize_sendheaders_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);
