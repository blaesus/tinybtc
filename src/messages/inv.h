#include "shared.h"

#define IV_TYPE_ERROR 0
#define IV_TYPE_MSG_TX 1
#define IV_TYPE_MSG_BLOCK 2
#define IV_TYPE_MSG_FILTERED_BLOCK 3
#define IV_TYPE_MSG_CMPCT_BLOCK 4

typedef GenericDataPayload InvPayload;

int32_t parse_into_inv_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_inv_message(Message *ptrMessage);

char *get_iv_type(uint32_t type);
