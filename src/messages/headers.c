#include <stdlib.h>
#include "headers.h"
#include "util.h"

uint64_t parse_headers_payload(
    Byte *ptrBuffer,
    HeadersPayload *ptrPayload
) {
    Byte *p = ptrBuffer;
    p += parse_varint(p, &ptrPayload->count);
    for (uint64_t i = 0; i < ptrPayload->count; i++) {
        p += parse_block_payload_header(p, &ptrPayload->headers[i].header);
        p += parse_varint(p, &ptrPayload->headers[i].transactionCount);
    }
    return ptrBuffer - p;
}

int32_t parse_into_headers_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = {0};
    HeadersPayload payload = {0};
    parse_message_header(ptrBuffer, &header);
    parse_headers_payload(ptrBuffer + sizeof(header), &payload);
    memcpy(ptrMessage, &header, sizeof(header));
    ptrMessage->ptrPayload = malloc(sizeof(HeadersPayload));
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(payload));
    return 0;
}

void print_headers_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    HeadersPayload *ptrPayload = (HeadersPayload *)ptrMessage->ptrPayload;
    printf("payload: count=%llu\n", ptrPayload->count);
}
