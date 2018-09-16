#include <stdint.h>
#include <stdlib.h>
#include "messages/shared.h"
#include "reject.h"

uint64_t parse_reject_payload(
    Byte *ptrBuffer,
    RejectPayload *ptrRejectPayload
) {
    Byte *p = ptrBuffer;
    p += parse_as_varstr(p, &ptrRejectPayload->message);
    p += PARSE_INTO(p, &ptrRejectPayload->ccode);
    p += parse_as_varstr(p, &ptrRejectPayload->reason);
    p += PARSE_INTO(p, &ptrRejectPayload->data);
    return p - ptrBuffer;
}

int32_t parse_into_reject_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = get_empty_header();
    parse_message_header(ptrBuffer, &header);
    memcpy(ptrMessage, &header, sizeof(header));

    RejectPayload payload;
    memset(&payload, 0, sizeof(payload));
    parse_reject_payload(ptrBuffer + sizeof(header), &payload);
    ptrMessage->ptrPayload = malloc(sizeof(RejectPayload)); // parse_message:payload
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(payload));
    return 0;
}

void print_reject_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    RejectPayload *ptrPayload = (RejectPayload *)ptrMessage->ptrPayload;
    printf("payload: ccode=%u, reason is '%s'\n",
           ptrPayload->ccode,
           ptrPayload->reason.string
    );
}
