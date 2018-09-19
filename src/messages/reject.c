#include <stdint.h>
#include <stdlib.h>
#include "util.h"
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
    ptrMessage->ptrPayload = MALLOC(sizeof(RejectPayload), "parse_message:payload");
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(payload));
    return 0;
}

void print_reject_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    RejectPayload *ptrPayload = (RejectPayload *)ptrMessage->ptrPayload;
    char *reason = CALLOC(1, MAX_VARIABLE_LENGTH_STRING_LENGTH, "print_reject_message:reason");
    memcpy(ptrPayload->reason.string, reason, ptrPayload->reason.length);
    printf("payload: ccode=%u, reason is '%s'\n",
           ptrPayload->ccode,
           reason
    );
    FREE(reason, "print_reject_message:reason");
}
