#pragma once
#include <stdint.h>
#include "datatypes.h"
#include "messages/shared.h"

struct PingpongPayload {
    uint64_t nonce;
};

typedef struct PingpongPayload PingpongPayload;

uint64_t serialize_pingpong_payload(
    PingpongPayload *ptrPayload,
    Byte *ptrBuffer
);

uint64_t serialize_pingpong_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
);

int32_t make_ping_message(
    Message *ptrMessage,
    PingpongPayload *ptrPayload
);

int32_t make_pong_message(
    Message *ptrMessage,
    PingpongPayload *ptrPayload
);

int32_t parse_into_pingpong_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_pingpong_message(Message *ptrMessage);
