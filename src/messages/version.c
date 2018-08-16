#include <stdint.h>
#include <stdlib.h>

#include "messages/header.h"

#include "version.h"
#include "shared.h"
#include "globalstate.h"
#include "peer.h"
#include "util.h"

uint64_t serialize_version_payload(
    struct VersionPayload *ptrPayload,
    uint8_t *ptrBuffer,
    uint32_t bufferSize
) {
    if (bufferSize < 0) {
        // TODO: Check buffer overflow in the following procedures;
        return 0;
    }
    uint8_t *p = ptrBuffer;
    uint64_t offset = 0;

    memcpy(p, &ptrPayload->version, sizeof(ptrPayload->version));
    p += sizeof(ptrPayload->version);

    memcpy(p, &ptrPayload->services, sizeof(ptrPayload->services));
    p += sizeof(ptrPayload->services);

    memcpy(p, &ptrPayload->timestamp, sizeof(ptrPayload->timestamp));
    p += sizeof(ptrPayload->timestamp);

    offset = serialize_network_address(&ptrPayload->addr_recv, p, bufferSize);
    p += offset;

    offset = serialize_network_address(&ptrPayload->addr_from, p, bufferSize);
    p += offset;

    memcpy(p, &ptrPayload->nonce, sizeof(ptrPayload->nonce));
    p += sizeof(ptrPayload->nonce);

    uint64_t varStrLength = serialize_varstr(&ptrPayload->user_agent, p);
    p += varStrLength;

    memcpy(p, &global.blockchainHeight, sizeof(global.blockchainHeight));
    p += sizeof(global.blockchainHeight);

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

    uint32_t userAgentDataLength = (uint32_t)strlen((char *)parameters.userAgent);

    ptrPayload->version = parameters.protocolVersion;
    ptrPayload->services = parameters.services;
    ptrPayload->timestamp = time(NULL);
    ptrPayload->addr_recv = recipientAddress;
    ptrPayload->addr_from = global.myAddress;
    ptrPayload->nonce = nonce;
    ptrPayload->user_agent.length = userAgentDataLength;
    strcpy((char *)ptrPayload->user_agent.string, (char *)parameters.userAgent);
    ptrPayload->relay = true;

    uint8_t userAgentLengthWidth = calc_number_varint_width(userAgentDataLength);

    return userAgentDataLength + userAgentLengthWidth + 85;
}

int32_t make_version_message(
    struct Message *ptrMessage,
    Peer *ptrPeer
) {
    struct VersionPayload payload = {0};
    uint32_t payloadLength = make_version_payload(&payload, ptrPeer);
    uint8_t checksumCalculationBuffer[MESSAGE_BUFFER_SIZE] = {0};
    serialize_version_payload(&payload, checksumCalculationBuffer, MESSAGE_BUFFER_SIZE);
    ptrMessage->header.magic = parameters.magic;
    strcpy((char *)ptrMessage->header.command, CMD_VERSION);
    ptrMessage->header.length = payloadLength;
    ptrMessage->payload = malloc(sizeof(struct VersionPayload));
    memcpy(ptrMessage->payload, &payload, sizeof(struct VersionPayload));
    calculate_payload_checksum(
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
        (struct VersionPayload *)ptrMessage->payload,
        ptrBuffer+messageHeaderSize,
        1000
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

    struct NetworkAddress recipientAddress = {0};
    uint64_t recipientAddressWidth = parse_network_address(p, &recipientAddress);
    ptrPayload->addr_recv = recipientAddress;
    p += recipientAddressWidth;

    if (ptrPayload->version >= 106) {
        struct NetworkAddress senderAddress = {0};
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
    Header header = {0};
    struct VersionPayload payload = {0};
    parse_message_header(ptrBuffer, &header);
    parse_version_payload(ptrBuffer + sizeof(header), &payload);
    memcpy(ptrMessage, &header, sizeof(header));
    ptrMessage->payload = malloc(sizeof(struct VersionPayload));
    memcpy(ptrMessage->payload, &payload, sizeof(payload));
    return 0;
}

void print_version_message(struct Message *ptrMessage) {
    print_message_header(ptrMessage->header);
    VersionPayload* payload = (VersionPayload *)ptrMessage->payload;
    printf("payload: version=%u, user_agent=%s\n",
           payload->version,
           payload->user_agent.string
    );
}
