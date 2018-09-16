#include <stdint.h>
#include <stdlib.h>

#include "messages/header.h"

#include "version.h"
#include "shared.h"
#include "globalstate.h"
#include "peer.h"
#include "util.h"
#include "config.h"

uint64_t serialize_version_payload(
    struct VersionPayload *ptrPayload,
    uint8_t *ptrBuffer
) {
    uint8_t *p = ptrBuffer;
    uint64_t offset = 0;

    memcpy(p, &ptrPayload->version, sizeof(ptrPayload->version));
    p += sizeof(ptrPayload->version);

    memcpy(p, &ptrPayload->services, sizeof(ptrPayload->services));
    p += sizeof(ptrPayload->services);

    memcpy(p, &ptrPayload->timestamp, sizeof(ptrPayload->timestamp));
    p += sizeof(ptrPayload->timestamp);

    offset = serialize_network_address(&ptrPayload->addr_recv, p);
    p += offset;

    offset = serialize_network_address(&ptrPayload->addr_from, p);
    p += offset;

    memcpy(p, &ptrPayload->nonce, sizeof(ptrPayload->nonce));
    p += sizeof(ptrPayload->nonce);

    uint64_t varStrLength = serialize_varstr(&ptrPayload->user_agent, p);
    p += varStrLength;

    memcpy(p, &global.mainTip.context.height, sizeof(global.mainTip.context.height));
    p += sizeof(global.mainTip.context.height);

    bool relay = ptrPayload->relay;
    memcpy(p, &relay, sizeof(relay));
    p += sizeof(relay);

    return (p - ptrBuffer);
}


uint32_t make_version_payload(
    struct VersionPayload *ptrPayload,
    struct Peer *ptrPeer
) {
    struct NetworkAddress recipientAddress = ptrPeer->address;
    uint64_t nonce = random_uint64();

    uint32_t userAgentDataLength = (uint32_t)strlen((char *)config.userAgent);

    ptrPayload->version = config.protocolVersion;
    ptrPayload->services = config.services;
    ptrPayload->timestamp = time(NULL);
    ptrPayload->addr_recv = recipientAddress;
    ptrPayload->addr_from = global.myAddress;
    ptrPayload->nonce = nonce;
    ptrPayload->user_agent.length = userAgentDataLength;
    ptrPayload->start_height = global.mainTip.context.height;
    strcpy((char *)ptrPayload->user_agent.string, (char *)config.userAgent);
    ptrPayload->relay = true;

    uint8_t userAgentLengthWidth = calc_number_varint_width(userAgentDataLength);

    return userAgentDataLength + userAgentLengthWidth + 85;
}

int32_t make_version_message(
    struct Message *ptrMessage,
    Peer *ptrPeer
) {
    VersionPayload payload;
    memset(&payload, 0, sizeof(payload));
    uint32_t payloadLength = make_version_payload(&payload, ptrPeer);
    uint8_t checksumCalculationBuffer[MESSAGE_BUFFER_LENGTH] = {0};
    serialize_version_payload(&payload, checksumCalculationBuffer);
    ptrMessage->header.magic = mainnet.magic;
    strcpy((char *)ptrMessage->header.command, CMD_VERSION);
    ptrMessage->header.length = payloadLength;
    ptrMessage->ptrPayload = malloc(sizeof(VersionPayload)); // make_message_payload
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(VersionPayload));
    calculate_data_checksum(
        checksumCalculationBuffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_version_message(
    struct Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = 24;
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_version_payload(
        (struct VersionPayload *)ptrMessage->ptrPayload,
        ptrBuffer+messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

uint64_t parse_version_payload(
    uint8_t *ptrBuffer,
    struct VersionPayload *ptrPayload
) {
    uint8_t *p = ptrBuffer;

    memcpy(&ptrPayload->version, p, sizeof(ptrPayload->version));
    p += sizeof ptrPayload->version;

    memcpy(&ptrPayload->services, p, sizeof(ptrPayload->services));
    p += sizeof ptrPayload->services;

    memcpy(&ptrPayload->timestamp, p, sizeof(ptrPayload->timestamp));
    p += sizeof ptrPayload->timestamp;

    NetworkAddress recipientAddress;
    memset(&recipientAddress, 0, sizeof(recipientAddress));
    uint64_t recipientAddressWidth = parse_network_address(p, &recipientAddress);
    ptrPayload->addr_recv = recipientAddress;
    p += recipientAddressWidth;

    if (ptrPayload->version >= 106) {
        NetworkAddress senderAddress;
        memset(&senderAddress, 0, sizeof(senderAddress));
        uint64_t sendAddressWidth = parse_network_address(p, &senderAddress);
        ptrPayload->addr_from = senderAddress;
        p += sendAddressWidth;

        memcpy(&ptrPayload->nonce, p, sizeof(ptrPayload->nonce));
        p += sizeof ptrPayload->nonce;

        struct VariableLengthString userAgent = {.length = 0, .string={0}};
        uint64_t userAgentOffset = parse_as_varstr(p, &userAgent);
        ptrPayload->user_agent = userAgent;
        p += userAgentOffset;

        memcpy(&ptrPayload->start_height, p, sizeof(ptrPayload->start_height));
        p += sizeof ptrPayload->start_height;
    }

    if (ptrPayload->version >= 70001) {
        memcpy(&ptrPayload->relay, p, sizeof(ptrPayload->relay));
        p += sizeof ptrPayload->relay;
    }

    return p - ptrBuffer;
}

int32_t parse_into_version_message(
    Byte *ptrBuffer,
    Message *ptrMessage
) {
    Header header = get_empty_header();
    VersionPayload payload;
    memset(&payload, 0, sizeof(payload));
    parse_message_header(ptrBuffer, &header);
    parse_version_payload(ptrBuffer + sizeof(header), &payload);
    memcpy(ptrMessage, &header, sizeof(header));
    ptrMessage->ptrPayload = malloc(sizeof(struct VersionPayload)); // parse_message:payload
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(payload));
    return 0;
}

void print_version_message(struct Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    VersionPayload* payload = (VersionPayload *)ptrMessage->ptrPayload;
    printf("payload: version=%u, user_agent=%s\n",
           payload->version,
           payload->user_agent.string
    );
}
