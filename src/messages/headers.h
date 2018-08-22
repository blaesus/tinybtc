#pragma once

#include "datatypes.h"
#include "messages/block.h"

// @see https://en.bitcoin.it/wiki/Protocol_documentation#headers

#define MAX_HEAD_PER_PAYLOAD 2000

struct HeaderData {
    VarIntMem transactionCount;
    BlockPayloadHeader header;
};

struct HeadersPayload {
    VarIntMem count;
    struct HeaderData headers[MAX_HEAD_PER_PAYLOAD];
};

typedef struct HeadersPayload HeadersPayload;

int32_t parse_into_headers_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_headers_message(Message *ptrMessage);
