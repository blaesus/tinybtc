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
    p += SERIALIZE_TO(ptrPayload->version, p);
    p += SERIALIZE_TO(ptrPayload->services, p);
    p += SERIALIZE_TO(ptrPayload->timestamp, p);
    p += serialize_network_address(&ptrPayload->addr_recv, p);
    p += serialize_network_address(&ptrPayload->addr_from, p);
    p += SERIALIZE_TO(ptrPayload->nonce, p);
    p += serialize_varstr(&ptrPayload->user_agent, p);
    p += SERIALIZE_TO(global.mainTip.context.height, p);
    p += SERIALIZE_TO(ptrPayload->relay, p);
    return p - ptrBuffer;
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
    ptrMessage->ptrPayload = MALLOC(sizeof(VersionPayload), "make_message:payload");
    memcpy(ptrMessage->ptrPayload, &payload, sizeof(VersionPayload));
    calculate_data_checksum(
        checksumCalculationBuffer,
        ptrMessage->header.length,
        ptrMessage->header.checksum
    );
    return 0;
}

uint64_t serialize_version_message(
    Message *ptrMessage,
    uint8_t *ptrBuffer
) {
    uint64_t messageHeaderSize = 24;
    memcpy(ptrBuffer, ptrMessage, messageHeaderSize);
    serialize_version_payload(
        (VersionPayload *)ptrMessage->ptrPayload,
        ptrBuffer+messageHeaderSize
    );
    return messageHeaderSize + ptrMessage->header.length;
}

uint64_t parse_version_payload(
    uint8_t *ptrBuffer,
    struct VersionPayload *ptrPayload
) {
    uint8_t *p = ptrBuffer;
    p += PARSE_INTO(p, &ptrPayload->version);
    p += PARSE_INTO(p, &ptrPayload->services);
    p += PARSE_INTO(p, &ptrPayload->timestamp);
    p += parse_network_address(p, &ptrPayload->addr_recv);

    if (ptrPayload->version >= 106) {
        p += parse_network_address(p, &ptrPayload->addr_from);
        p += PARSE_INTO(p, &ptrPayload->nonce);
        p += parse_as_varstr(p, &ptrPayload->user_agent);
        p += PARSE_INTO(p, &ptrPayload->start_height);
    }

    if (ptrPayload->version >= 70001) {
        p += PARSE_INTO(p, &ptrPayload->relay);
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
    ptrMessage->ptrPayload = MALLOC(sizeof(struct VersionPayload), "make_message:payload");
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
