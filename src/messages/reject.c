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
    Header header = {0};
    parse_message_header(ptrBuffer, &header);
    memcpy(ptrMessage, &header, sizeof(header));

    RejectPayload payload = {0};
    parse_reject_payload(ptrBuffer + sizeof(header), &payload);
    ptrMessage->ptrPayload = malloc(sizeof(RejectPayload));
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
