#pragma once

#include <stdint.h>
#include "messages/shared.h"

#define MSG_WITNESS_FLAG (1 << 30);
#define MSG_TYPE_MASK    (0xffffffff >> 2);

#define IV_TYPE_ERROR 0
#define IV_TYPE_MSG_TX 1
#define IV_TYPE_MSG_BLOCK 2
#define IV_TYPE_MSG_FILTERED_BLOCK 3
#define IV_TYPE_MSG_CMPCT_BLOCK 4
#define IV_TYPE_WITNESS_BLOCK (IV_TYPE_MSG_BLOCK | MSG_WITNESS_FLAG)
#define IV_TYPE_WITNESS_TX (MSG_TX | MSG_WITNESS_FLAG)
#define IV_TYPE_FILTERED_WITNESS_BLOCK (MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG)

int32_t make_header_only_message(
    Message *ptrMessage,
    char* command,
    uint16_t commandLength
);

uint64_t serialize_header_only_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);

int32_t parse_into_iv_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_iv_message(Message *ptrMessage);

int32_t make_iv_message(
    Message *ptrMessage,
    GenericIVPayload *ptrPayload,
    Byte *command,
    uint32_t commandSize
);

uint64_t serialize_iv_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);
