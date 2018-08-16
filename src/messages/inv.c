#include <stdlib.h>

#include "inv.h"
#include "header.h"

static uint64_t parse_inv_payload(
    Byte *ptrBuffer,
    InvPayload *ptrPayload
) {
    uint64_t count = 0;
    uint8_t countWidth = parse_varint(ptrBuffer, &count);
    ptrPayload->count = count;
    for (uint64_t index = 0; index < count; index++) {
        memcpy(
            &ptrPayload->inventory[index],
            ptrBuffer + countWidth + index * sizeof(InventoryVector),
            sizeof(InventoryVector)
        );
    }
    return countWidth + count * sizeof(InventoryVector);
}

int32_t parse_into_inv_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = {0};
    InvPayload payload = {0};
    parse_message_header(ptrBuffer, &header);
    parse_inv_payload(ptrBuffer + sizeof(header), &payload);
    memcpy(ptrMessage, &header, sizeof(header));
    ptrMessage->payload = malloc(sizeof(InvPayload));
    memcpy(ptrMessage->payload, &payload, sizeof(payload));
    return 0;
}

void print_inv_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    InvPayload *ptrPayload = (InvPayload *)ptrMessage->payload;
    printf("payload: count=%llu\n",
           ptrPayload->count
    );
    for (uint8_t i = 0; i < ptrPayload->count; i++) {
        InventoryVector iv = ptrPayload->inventory[i];
        char *typeString = get_iv_type(iv.type);
        printf("Inventory of type %s(%u)\n", typeString, iv.type);
    }
}

char *get_iv_type(uint32_t type) {
    static char result[255] = {0};
    switch (type) {
        case IV_TYPE_ERROR: {
            strcpy(result, "ERROR");
            break;
        }
        case IV_TYPE_MSG_TX: {
            strcpy(result, "MSG_TX");
            break;
        }
        case IV_TYPE_MSG_BLOCK: {
            strcpy(result, "MSG_BLOCK");
            break;
        }
        case IV_TYPE_MSG_FILTERED_BLOCK: {
            strcpy(result, "MSG_FILTERED_BLOCK");
            break;
        }
        case IV_TYPE_MSG_CMPCT_BLOCK: {
            strcpy(result, "MSG_CMPCT_BLOCK");
            break;
        }
        default: {
            strcpy(result, "Unknown");
        }
    }
    return result;
}

