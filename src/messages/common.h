#pragma once

#include <stdint.h>
#include "messages/shared.h"

int32_t make_header_only_message(
    Message *ptrMessage,
    char* command,
    uint16_t commandLength
);

uint64_t serialize_header_only_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);
