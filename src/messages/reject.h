#pragma once

#include <datatypes.h>
#include <messages/shared.h>

#define MAX_REJECT_DATA 1024

#define REJECT_MALFORMED 0x01
#define REJECT_INVALID 0x10
#define REJECT_OBSOLETE 0x11
#define REJECT_DUPLICATE 0x12
#define REJECT_NONSTANDARD 0x40
#define REJECT_DUST 0x41
#define REJECT_INSUFFICIENTFEE 0x42
#define REJECT_CHECKPOINT 0x43

struct RejectPayload {
    struct VariableLengthString message;
    Byte ccode;
    struct VariableLengthString reason;
    Byte data[32];
};

typedef struct RejectPayload RejectPayload;

int32_t parse_into_reject_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_reject_message(Message *ptrMessage);
