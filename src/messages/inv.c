#include <stdlib.h>

#include "inv.h"
#include "header.h"
#include "common.h"

int32_t parse_into_inv_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    return parse_into_iv_message(ptrBuffer, ptrMessage);
}

void print_inv_message(Message *ptrMessage) {
    print_iv_message(ptrMessage);
}

