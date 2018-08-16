#pragma once
#include <stdint.h>
#include "shared.h"

uint64_t serialize_verack_message(
    Message *ptrMessage,
    Byte *ptrBuffer
);

int32_t parse_into_verack_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

int32_t make_verack_message(
    Message *ptrMessage
);

void print_verack_message(Message *ptrMessage);

