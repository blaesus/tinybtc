#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "uv/uv.h"

#include "communication.h"
#include "globalstate.h"
#include "networking.h"
#include "util.h"
#include "units.h"
#include "blockchain.h"
#include "config.h"
#include "peer.h"
#include "persistent.h"

#include "messages/common.h"
#include "messages/shared.h"
#include "messages/version.h"
#include "messages/verack.h"
#include "messages/inv.h"
#include "messages/addr.h"
#include "messages/getaddr.h"
#include "messages/blockreq.h"
#include "messages/sendheaders.h"
#include "messages/reject.h"
#include "messages/pingpong.h"
#include "messages/headers.h"
#include "messages/print.h"

void send_getheaders(uv_tcp_t *socket);
void send_getdata_for_block(uv_tcp_t *socket, Byte *hash);

bool peerHandShaken(Peer *ptrPeer) {
    return ptrPeer->handshake.acceptUs && ptrPeer->handshake.acceptThem;
}

void on_handle_close(uv_handle_t *handle) {
    SocketContext *data = (SocketContext *)handle->data;
    connect_to_random_addr_for_peer(data->peer->index);
}

void timeout_peers() {
    time_t now = time(NULL);
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = &global.peers[i];
        bool timeoutForLateHandshake =
            (now - ptrPeer->connectionStart > PEER_CONNECTION_TIMEOUT_SEC)
            && !peerHandShaken(ptrPeer);

        time_t ping = ptrPeer->requests.ping.pingSent;
        time_t pong = ptrPeer->requests.ping.pongReceived;
        bool neverReceivedPong = pong == 0;
        bool timeoutForLatePong = ping && (
            neverReceivedPong ? now - ping > config.maxPingLatency : pong - ping > config.maxPingLatency
        );

        if (timeoutForLateHandshake || timeoutForLatePong) {
            printf("Timeout peer %u (reason: handshake=%u, pong=%u)\n", i, timeoutForLateHandshake, timeoutForLatePong);
            if (timeoutForLateHandshake || neverReceivedPong) {
                disable_ip(ptrPeer->address.ip);
            }
            uv_handle_t *ptrHandle = (uv_handle_t *)&ptrPeer->socket;
            if (ptrHandle && !uv_is_closing(ptrHandle)) {
                SocketContext *ptrData = calloc(1, sizeof(SocketContext));
                ptrData->peer = ptrPeer;
                ptrHandle->data = ptrData;
                uv_close(ptrHandle, on_handle_close);
            }
        }
    }
}

void data_exchange_with_peer(Peer *ptrPeer) {
    printf("Executing data exchange with peer %u (%s)\n", ptrPeer->index, convert_ipv4_readable(ptrPeer->address.ip));
    if (ptrPeer->chain_height > global.mainTip.context.height) {
        send_getheaders(&ptrPeer->socket);
    }
    else if (ptrPeer->chain_height == global.mainTip.context.height && is_hash_empty(ptrPeer->requests.block)) {
        SHA256_HASH nextMissingBlock = {0};
        int8_t status = get_next_missing_block(nextMissingBlock);
        if (!status) {
            print_hash_with_description("requesting block: ", nextMissingBlock);
            send_getdata_for_block(&ptrPeer->socket, nextMissingBlock);
            memcpy(ptrPeer->requests.block, nextMissingBlock, SHA256_LENGTH);
        }
        else {
            printf("Block sync status %i\n", status);
        }
    }
    else {
        // Peers has less data
    }
}

void request_data_from_peers() {
    printf("Requesting data from peers...\n");
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = &global.peers[i];
        if (!peerHandShaken(ptrPeer)) {
            continue;
        }
        data_exchange_with_peer(ptrPeer);
    }
}

uint16_t print_node_status() {
    printf("\n==== Node status ====\n");

    printf("peers handshake: ");
    uint16_t validPeers = 0;
    for (uint32_t i = 0; i < global.peerCount; i++) {
        if (peerHandShaken(&global.peers[i])) {
            validPeers++;
            printf("O ");
        }
        else {
            printf("X ");
        }
    }
    printf(" (%u/%u)\n", validPeers, global.peerCount);
    printf("%u addresses\n", global.peerAddressCount);


    printf("main chain height %u\n", global.mainTip.context.height);
    print_hash_with_description("main chain tip at ", global.mainTip.meta.hash);
    printf("=====================\n");
    return validPeers;
}

void ping_peers() {
    printf("Pinging peers\n");
    // TODO: Use at least milliseconds. Seconds are too crude.
    time_t now = time(NULL);
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = &global.peers[i];
        if (!peerHandShaken(ptrPeer)) {
            continue;
        }
        ptrPeer->requests.ping.nonce = random_uint64();
        ptrPeer->requests.ping.pingSent = now;
        ptrPeer->requests.ping.pongReceived = 0;
        PingpongPayload ptrPayload = {
            .nonce = ptrPeer->requests.ping.nonce
        };
        send_message(&ptrPeer->socket, CMD_PING, &ptrPayload);
    }
}

void on_interval(uv_timer_t *handle) {
    time_t now = time(NULL);
    time_t deltaT = now - global.start_time;
    timeout_peers();
    if (deltaT % config.peerDataRequestPeriod == 0) {
        request_data_from_peers();
    }
    if (deltaT % config.autoSavePeriod == 0) {
        save_chain_data();
    }
    if (deltaT % config.pingPeriod == 0) {
        ping_peers();
    }
    print_node_status();
    if ((config.autoExitPeriod > 0) && (deltaT >= config.autoExitPeriod)) {
        printf("Stopping main loop...\n");
        uv_timer_stop(handle);
        uv_stop(uv_default_loop());
        uv_loop_close(uv_default_loop());
        printf("Done.\n");
    }
}

uint32_t setup_main_event_loop() {
    printf("Setting up main event loop...");
    uv_loop_init(uv_default_loop());
    uv_timer_init(uv_default_loop(), &global.mainTimer);
    uv_timer_start(&global.mainTimer, &on_interval, 0, config.mainTimerInterval);
    printf("Done.\n");
    return 0;
}

void send_getheaders(uv_tcp_t *socket) {
    uint32_t hashCount = 1;

    BlockRequestPayload payload = {
        .version = config.protocolVersion,
        .hashCount = hashCount,
        .hashStop = {0}
    };
    memcpy(&payload.blockLocatorHash[0], global.mainTip.meta.hash, SHA256_LENGTH);

    send_message(socket, CMD_GETHEADERS, &payload);
}

void send_getdata_for_block(uv_tcp_t *socket, Byte *hash) {
    GenericIVPayload payload = {
        .count = 1,
    };
    InventoryVector iv = {
        .type = IV_TYPE_MSG_BLOCK,
    };
    memcpy(iv.hash, hash, SHA256_LENGTH);
    payload.inventory[0] = iv;
    send_message(socket, CMD_GETDATA, &payload);
}

char *get_ip_from_context(void *data) {
    return convert_ipv4_readable(((SocketContext *)data)->peer->address.ip);
}

int32_t parse_buffer_into_message(
    uint8_t *ptrBuffer,
    Message *ptrMessage
) {
    Header header = get_empty_header();
    parse_message_header(ptrBuffer, &header);
    char *command = (char *)header.command;
    if (strcmp(command, CMD_VERSION) == 0) {
        return parse_into_version_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        return parse_into_verack_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        return parse_into_inv_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        return parse_into_addr_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_REJECT) == 0) {
        return parse_into_reject_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        return parse_into_pingpong_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        return parse_into_pingpong_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_HEADERS) == 0) {
        return parse_into_headers_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_BLOCK) == 0) {
        return parse_into_block_message(ptrBuffer, ptrMessage);
    }
    else {
        fprintf(stderr, "Cannot parse message with unknown command '%s'\n", command);
        return 1;
    }
}

void on_message_sent(uv_write_t *writeRequest, int status) {
    struct WriteContext *ptrContext = writeRequest->data;

    char *ipString = get_ip_from_context(ptrContext);
    if (status) {
        fprintf(stderr, "failed to send message to %s: %s \n", ipString, uv_strerror(status));
        connect_to_random_addr_for_peer(ptrContext->peer->index);
        return;
    }
    else {
        printf("message sent to %s\n", ipString);
    }
    free(ptrContext->ptrBufferBase);
    free(ptrContext);
    free(writeRequest);
}

void write_buffer_to_socket(
    uv_buf_t *ptrUvBuffer,
    uv_tcp_t *socket
) {
    SocketContext *ptrSocketContext = socket->data;
    struct WriteContext *ptrWriteContext = calloc(1, sizeof(*ptrWriteContext));
    ptrWriteContext->peer = ptrSocketContext->peer;
    ptrWriteContext->ptrBufferBase = ptrUvBuffer->base;
    uv_write_t *ptrWriteReq = calloc(1, sizeof(uv_write_t));
    uint8_t bufferCount = 1;
    ptrWriteReq->data = ptrWriteContext;
    uv_write(ptrWriteReq, (uv_stream_t *)socket, ptrUvBuffer, bufferCount, &on_message_sent);
}

void send_message(uv_tcp_t *socket, char *command, void *ptrData) {
    Message message = get_empty_message();
    SocketContext *ptrContext = (SocketContext *)socket->data;
    Byte *buffer = malloc(MESSAGE_BUFFER_LENGTH);
    uv_buf_t uvBuffer = uv_buf_init((char *)buffer, sizeof(buffer));
    uvBuffer.base = (char *)buffer;

    uint64_t dataSize = 0;

    if (strcmp(command, CMD_VERSION) == 0) {
        make_version_message(&message, ptrContext->peer);
        dataSize = serialize_version_message(&message, buffer);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        make_verack_message(&message);
        dataSize = serialize_verack_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETADDR) == 0) {
        make_getaddr_message(&message);
        dataSize = serialize_getaddr_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETDATA) == 0) {
        GenericIVPayload *ptrPayload = ptrData;
        make_iv_message(
            &message,
            ptrPayload,
            (Byte *)CMD_GETDATA,
            sizeof(CMD_GETDATA)
        );
        dataSize = serialize_iv_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETHEADERS) == 0) {
        BlockRequestPayload *ptrPayload = ptrData;
        make_blockreq_message(&message, ptrPayload, CMD_GETHEADERS, sizeof(CMD_GETHEADERS));
        dataSize = serialize_blockreq_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETBLOCKS) == 0) {
        BlockRequestPayload *ptrPayload = ptrData;
        make_blockreq_message(&message, ptrPayload, CMD_GETBLOCKS, sizeof(CMD_GETBLOCKS));
        dataSize = serialize_blockreq_message(&message, buffer);
    }
    else if (strcmp(command, CMD_SENDHEADERS) == 0) {
        make_sendheaders_message(&message);
        dataSize = serialize_sendheaders_message(&message, buffer);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        PingpongPayload *ptrPayload = ptrData;
        make_ping_message(&message, ptrPayload);
        dataSize = serialize_pingpong_message(&message, buffer);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        PingpongPayload *ptrPayload = ptrData;
        make_pong_message(&message, ptrPayload);
        dataSize = serialize_pingpong_message(&message, buffer);
    }
    else if (strcmp(command, XCMD_BINARY) == 0) {
        struct VariableLengthString *ptrPayload = ptrData;
        dataSize = ptrPayload->length;
        memcpy(buffer, ptrPayload->string, dataSize);
    }
    else {
        fprintf(stderr, "send_message: Cannot recognize command %s", command);
        return;
    }
    uvBuffer.len = dataSize;

    char *ipString = get_ip_from_context(socket->data);
    if (strcmp(command, XCMD_BINARY) == 0) {
        printf("Sending binary to peer %s\n", ipString);
        print_object((Byte *)uvBuffer.base, uvBuffer.len);
    }
    else {
        printf(
            "Sending message %s to peer %s\n",
            message.header.command,
            ipString
        );
    }
    write_buffer_to_socket(&uvBuffer, socket);
    free(message.ptrPayload);
}

void on_handshake_success(Peer *ptrPeer) {
    data_exchange_with_peer(ptrPeer);
    bool shouldSendGetaddr = global.peerAddressCount < config.getaddrThreshold;
    if (shouldSendGetaddr) {
        send_message(&ptrPeer->socket, CMD_GETADDR, NULL);
    }
}

void handle_incoming_message(
    Peer *ptrPeer,
    Message message
) {
    print_message(&message);
    uint32_t now = (uint32_t)time(NULL);
    set_addr_timestamp(ptrPeer->address.ip, now);

    char *command = (char *)message.header.command;

    if (strcmp(command, CMD_VERSION) == 0) {
        VersionPayload *ptrPayloadTyped = message.ptrPayload;
        if (ptrPayloadTyped->version >= mainnet.minimalPeerVersion) {
            ptrPeer->handshake.acceptThem = true;
        }
        ptrPeer->chain_height = ptrPayloadTyped->start_height;
        set_addr_services(ptrPeer->address.ip, ptrPayloadTyped->services);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        ptrPeer->handshake.acceptUs = true;
        send_message(&ptrPeer->socket, CMD_VERACK, NULL);
        on_handshake_success(ptrPeer);
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        AddrPayload *ptrPayload = message.ptrPayload;
        uint64_t skipped = 0;
        for (uint64_t i = 0; i < ptrPayload->count; i++) {
            struct AddrRecord *record = &ptrPayload->addr_list[i];
            if (is_ipv4(record->net_addr.ip)) {
                uint32_t timestampForRecord = record->timestamp - HOUR(2);
                add_peer_address(record->net_addr, timestampForRecord);
            }
            else {
                skipped++;
            }
        }
        printf("Skipped %llu IPs\n", skipped);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        send_message(&ptrPeer->socket, CMD_PONG, message.ptrPayload);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        PingpongPayload *ptrPayload = message.ptrPayload;
        if (ptrPayload->nonce == ptrPeer->requests.ping.nonce) {
            ptrPeer->requests.ping.pongReceived = now;
        }
        else {
            printf("Unexpected pong nonce: received %llu, expecting %llu\n",
                ptrPayload->nonce, ptrPeer->requests.ping.nonce);
        }
    }
    else if (strcmp(command, CMD_HEADERS) == 0) {
        HeadersPayload *ptrPayload = message.ptrPayload;
        for (uint64_t i = 0; i < ptrPayload->count; i++) {
            BlockPayloadHeader *ptrHeader = &ptrPayload->headers[i].header;
            int8_t status = process_incoming_block_header(ptrHeader);
            if (status && status != HEADER_EXISTED) {
                printf("new header status %i\n", status);
            }
        }
    }
    else if (strcmp(command, CMD_BLOCK) == 0) {
        BlockPayload *ptrBlock = message.ptrPayload;
        process_incoming_block(ptrBlock);
        memset(ptrPeer->requests.block, 0, SHA256_LENGTH);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        // send_message(ptrPeer->connection, CMD_GETDATA, message.ptrPayload);
    }
}

bool checksum_match(Byte *ptrBuffer) {
    Header messageHeader = {0};
    parse_message_header(ptrBuffer, &messageHeader);
    PayloadChecksum checksum = {0};
    calculate_data_checksum(ptrBuffer + sizeof(messageHeader), messageHeader.length, checksum);
    return memcmp(checksum, messageHeader.checksum, CHECKSUM_SIZE) == 0;
}

int64_t find_first_magic(Byte *data, uint64_t maxLength) {
    Byte *p = data;
    while ((p - data + sizeof(mainnet.magic)) < maxLength) {
        if (starts_with_magic(p)) {
            return (int64_t)(p - data);
        }
        p++;
    }
    return -1;
}

void extract_message_from_stream_buffer(MessageCache *ptrCache, Peer *ptrPeer) {
    int64_t magicOffset = find_first_magic(ptrCache->buffer, ptrCache->bufferIndex);
    while (magicOffset >= 0) {
        if (magicOffset != 0) {
            memcpy(ptrCache->buffer, ptrCache->buffer + magicOffset, ptrCache->bufferIndex - magicOffset);
            ptrCache->bufferIndex -= magicOffset;
            printf("Trimmed preceding %llu non-magic bytes", magicOffset);
        }
        Header header;
        parse_message_header(ptrCache->buffer, &header);
        uint64_t messageSize = sizeof(Header) + header.length;
        printf("Message loading from %s: (%llu/%llu)\n",
            convert_ipv4_readable(ptrPeer->address.ip),
            ptrCache->bufferIndex,
            messageSize
        );
        if (ptrCache->bufferIndex >= messageSize) {
            Message message = get_empty_message();
            if (!checksum_match(ptrCache->buffer)) {
                printf("Payload checksum mismatch");
                print_message_header(header);
            }
            else {
                int32_t error = parse_buffer_into_message(ptrCache->buffer, &message);
                if (!error) {
                    handle_incoming_message(ptrPeer, message);
                }
            }
            memcpy(ptrCache->buffer, ptrCache->buffer + messageSize, ptrCache->bufferIndex - messageSize);
            ptrCache->bufferIndex -= messageSize;
            magicOffset = find_first_magic(ptrCache->buffer, ptrCache->bufferIndex);
        }
        else {
            break;
        }
    }
}

void on_incoming_segment(
    uv_stream_t *socket,
    ssize_t nread,
    const uv_buf_t *buf
) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) socket, NULL);
        }
        else {
            // file ended; noop
        }
        return;
    }
    SocketContext *ptrContext = (SocketContext *)socket->data;
    MessageCache *ptrCache = &(ptrContext->streamCache);
    memcpy(ptrCache->buffer + ptrCache->bufferIndex, buf->base, buf->len);
    ptrCache->bufferIndex += nread;
    free(buf->base);
    extract_message_from_stream_buffer(ptrCache, ptrContext->peer);
}

void allocate_read_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_peer_connect(uv_connect_t* connectRequest, int32_t error) {
    struct ConnectContext *ptrContext = (struct ConnectContext *)connectRequest->data;
    char *ipString = convert_ipv4_readable(ptrContext->peer->address.ip);
    if (error) {
        fprintf(
            stderr,
            "connection failed with peer %s: %s(%i) \n",
            ipString,
            uv_strerror(error),
            error
        );
        if (ptrContext->peer->relationship == REL_MY_SERVER) {
            disable_ip(ptrContext->peer->address.ip);
            connect_to_random_addr_for_peer(ptrContext->peer->index);
        }
    }
    else {
        printf("connected with peer %s \n", ipString);

        SocketContext *socketContext = calloc(1, sizeof(*socketContext));
        socketContext->peer = ptrContext->peer;
        connectRequest->handle->data = socketContext;
        send_message((uv_tcp_t *)connectRequest->handle, CMD_VERSION, NULL);
        uv_read_start(connectRequest->handle, allocate_read_buffer, on_incoming_segment);
    }
    free(connectRequest);
    free(ptrContext);
}

int32_t initialize_peer(uint32_t peerIndex, NetworkAddress addr)  {
    printf(
        "Initializing peer %u with IP %s \n",
        peerIndex,
        convert_ipv4_readable(addr.ip)
    );

    Peer *ptrPeer = &global.peers[peerIndex];

    reset_peer(ptrPeer);
    ptrPeer->index = peerIndex;
    ptrPeer->connectionStart = time(NULL);
    memcpy(ptrPeer->address.ip, addr.ip, sizeof(IP));

    // Connection request
    struct ConnectContext *ptrContext = calloc(1, sizeof(*ptrContext));
    ptrContext->peer = ptrPeer;
    uv_connect_t *ptrConnectRequest = calloc(1, sizeof(uv_connect_t));
    ptrConnectRequest->data = ptrContext;

    // TCP socket
    uv_tcp_init(uv_default_loop(), &ptrPeer->socket);

    // Connection request
    struct sockaddr_in remoteAddress = {0};
    uv_ip4_addr(convert_ipv4_readable(addr.ip), htons(addr.port), &remoteAddress);
    uv_tcp_connect(
        ptrConnectRequest,
        &ptrPeer->socket,
        (const struct sockaddr*)&remoteAddress,
        &on_peer_connect
    );
    return 0;
}

void on_incoming_connection(uv_stream_t *server, int status) {
    printf("Incoming connection\n");
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    uv_tcp_t *client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(uv_default_loop(), client);
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        printf("Accepted\n");
        uv_read_start((uv_stream_t *) client, allocate_read_buffer, on_incoming_segment);
    } else {
        printf("Cannot accept\n");
        uv_close((uv_handle_t*) client, NULL);
    }
}


int32_t setup_listen_socket() {
    printf("Setting up listen socket...");
    struct sockaddr_in localAddress = {0};
    uv_ip4_addr("0.0.0.0", mainnet.port, &localAddress);
    uv_tcp_init(uv_default_loop(), &global.listenSocket);
    uv_tcp_bind(&global.listenSocket, (const struct sockaddr*) &localAddress, 0);
    int32_t listenError = uv_listen(
            (uv_stream_t*) &global.listenSocket,
            config.backlog,
            on_incoming_connection);
    if (listenError) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(listenError));
        return 1;
    }
    printf("Done\n");
    return 0;
}

static NetworkAddress pick_random_addr() {
    uint32_t index = random_range(0, global.peerAddressCount - 1);
    return global.peerAddresses[index].net_addr;
}

static NetworkAddress pick_random_nonpeer_addr() {
    NetworkAddress addr;
    do {
        addr = pick_random_addr();
    } while (is_peer(addr.ip));
    return addr;
}

void connect_to_random_addr_for_peer(uint32_t peerIndex) {
    NetworkAddress addr = pick_random_nonpeer_addr();
    initialize_peer(peerIndex, addr);
}

int32_t connect_to_initial_peers() {
    uint32_t outgoing = min(config.maxOutgoing, global.peerAddressCount);
    for (uint32_t i = 0; i < outgoing; i++) {
        connect_to_random_addr_for_peer(i);
        global.peerCount += 1;
    }
    return 0;
}

int32_t release_sockets() {
    printf("Closing sockets...");
    for (uint32_t peerIndex = 0; peerIndex < global.peerCount; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        uv_handle_t* socket = (uv_handle_t*)&peer->socket;
        if (!uv_is_closing(socket)) {
            uv_read_stop((uv_stream_t *)&peer->socket);
            uv_close(socket, NULL);
        }
    }
    printf("Done.\n");
    return 0;
}
