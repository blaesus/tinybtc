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
        uint64_t dataWidth = parse_network_address_with_time(
            p,
            &ptrPayload->addr_list[i].net_addr
        );
        p += dataWidth;
    }
}

int32_t parse_into_addr_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = {0};
    parse_message_header(ptrBuffer, &header);
    memcpy(ptrMessage, &header, sizeof(header));

    AddrPayload payload = {0};
    parse_addr_payload(ptrBuffer + sizeof(header), &payload);
    ptrMessage->payload = malloc(sizeof(AddrPayload));
    memcpy(ptrMessage->payload, &payload, sizeof(payload));
    return 0;
}

void print_addr_message(Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    AddrPayload *ptrPayload = (AddrPayload *)ptrMessage->payload;
    printf("payload: count=%llu\n",
           ptrPayload->count
    );
    for (uint8_t i = 0; i < ptrPayload->count; i++) {
        AddrRecord record = ptrPayload->addr_list[i];
        char *ipString = convert_ipv4_readable(record.net_addr.ip);
        printf("Addr %u: %s\n", i, ipString);
        print_object(record.net_addr.ip, sizeof(IP));
    }
}
