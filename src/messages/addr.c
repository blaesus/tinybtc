#include <stdint.h>
#include <stdlib.h>

#include "messages/shared.h"
#include "messages/addr.h"
#include "networking.h"

void parse_addr_payload(
    Byte *ptrBuffer,
    AddrPayload *ptrPayload
) {
    Byte *p = ptrBuffer;
    uint8_t countWidth = parse_varint(ptrBuffer, &ptrPayload->count);
    p += countWidth;

    for (uint64_t i = 0; i < ptrPayload->count; i++) {
        AddrRecord *record = &ptrPayload->addr_list[i];

        memcpy(&record->timestamp, p, sizeof(uint32_t));
        p += sizeof(uint32_t);
        uint64_t networkAddressWidth = parse_network_address(
            p,
            &record->net_addr
        );
        p += networkAddressWidth;
    }
}

int32_t parse_into_addr_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = get_empty_header();
    parse_message_header(ptrBuffer, &header);
    memcpy(ptrMessage, &header, sizeof(header));

    AddrPayload payload;
    memset(&payload, 0, sizeof(payload));
    parse_addr_payload(ptrBuffer + sizeof(header), &payload);
    ptrMessage->ptrPayload = malloc(sizeof(AddrPayload)); // parse_message:payload
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(payload));
    return 0;
}

void print_addr_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    AddrPayload *ptrPayload = (AddrPayload *)ptrMessage->ptrPayload;
    AddrRecord record = ptrPayload->addr_list[0];
    char *ipString = convert_ipv4_readable(record.net_addr.ip);
    printf("payload: count=%llu, first being %s\n",
           ptrPayload->count,
           ipString
    );
}
