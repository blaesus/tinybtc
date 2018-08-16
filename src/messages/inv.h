#include "shared.h"

typedef GenericIVPayload InvPayload;

int32_t parse_into_inv_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_inv_message(Message *ptrMessage);
