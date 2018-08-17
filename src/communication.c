#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "uv/uv.h"

#include "communication.h"
#include "globalstate.h"
#include "networking.h"
#include "util.h"

#include "messages/shared.h"
#include "messages/version.h"
#include "messages/verack.h"
#include "messages/inv.h"
#include "messages/addr.h"
#include "messages/getaddr.h"
#include "messages/print.h"

void on_idle(uv_idle_t *handle) {
    global.eventCounter++;
    if (global.eventCounter % 1000000 == 0) {
        printf("Event count %llu\n", global.eventCounter);
    }
    if (global.eventCounter >= 5e7) {
        printf("Stopping main loop...\n");
        uv_idle_stop(handle);
        uv_loop_close(uv_default_loop());
        uv_stop(uv_default_loop());
        printf("Done.\n");
    }
}

uint32_t setup_main_event_loop(bool setupIdle) {
    printf("Setting up main event loop...");
    uv_loop_init(uv_default_loop());
    if (setupIdle) {
        uv_idle_init(uv_default_loop(), &global.idler);
        uv_idle_start(&global.idler, on_idle);
    }
    printf("Done.\n");
    return 0;
}

struct ContextData {
    struct Peer *peer;
};

typedef struct ContextData ContextData;

char *get_peer_ip(uv_connect_t *req) {
    ContextData *data = (ContextData *)req->data;
    return convert_ipv4_readable(data->peer->address.ip);
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
    else {
        fprintf(stderr, "Cannot parse message with unknown command '%s'\n", command);
        return 1;
    }
}

void on_message_sent(uv_write_t *req, int status) {
    char *ipString = get_peer_ip((uv_connect_t *)req);
    if (status) {
        fprintf(stderr, "failed to send message to %s: %s \n", ipString, uv_strerror(status));
        return;
    }
    else {
        printf("message sent to %s\n", ipString);
    }
}

void write_buffer(
        uv_connect_t *req,
        uv_buf_t *ptrUvBuffer
) {
    uv_stream_t* tcp = req->handle;
    uv_write_t *ptrWriteReq = (uv_write_t*)malloc(sizeof(uv_write_t));
    uint8_t bufferCount = 1;
    ptrWriteReq->data = req->data;
    uv_write(ptrWriteReq, tcp, ptrUvBuffer, bufferCount, &on_message_sent);
}

void send_message(
    uv_connect_t *req,
    char *command
) {
    Message message = get_empty_message();
    Byte buffer[MESSAGE_BUFFER_SIZE] = {0};
    uv_buf_t uvBuffer = uv_buf_init((char *)buffer, sizeof(buffer));
    uvBuffer.base = (char *)buffer;

    uint64_t dataSize = 0;

    if (strcmp(command, CMD_VERSION) == 0) {
        Peer *ptrPeer = ((ContextData *)(req->data))->peer;
        make_version_message(&message, ptrPeer);
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
    else {
        fprintf(stderr, "Cannot recognize command %s", command);
        return;
    }
    uvBuffer.len = dataSize;

    char *ipString = get_peer_ip(req);
    printf(
        "Sending %s to peer %s\n",
        message.header.command,
        ipString
    );
    write_buffer(req, &uvBuffer);
}


void on_incoming_message(
    Peer *ptrPeer,
    Message message
) {
    print_message(&message);

    char *command = (char *)message.header.command;

    if (strcmp(command, CMD_VERSION) == 0) {
        VersionPayload *ptrPayloadTyped = message.payload;
        if (ptrPayloadTyped->version >= parameters.minimalPeerVersion) {
            ptrPeer->handshake.acceptThem = true;
        }
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        ptrPeer->handshake.acceptUs = true;
        send_message(ptrPeer->connection, CMD_VERACK);
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        AddrPayload *ptrPayload = message.payload;
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
//        dedupe_global_addr_cache();
    }

    bool shouldSendGetaddr =
        global.peerAddressCount < parameters.getaddrThreshold
        && ptrPeer->handshake.acceptUs
        && ptrPeer->handshake.acceptThem
        && !ptrPeer->flags.attemptedGetaddr
    ;

    if (shouldSendGetaddr) {
        send_message(ptrPeer->connection, CMD_GETADDR);
        ptrPeer->flags.attemptedGetaddr = true;
    }

    uint32_t now = (uint32_t)time(NULL);
    set_addr_timestamp(ptrPeer->address.ip, now);
}

void reset_message_cache(
    MessageCache *ptrCache
) {
    ptrCache->bufferIndex = 0;
    ptrCache->expectedLength = 0;
    memset(ptrCache->buffer, 0, sizeof(ptrCache->buffer));
}

void on_incoming_data(
    uv_stream_t *client,
    ssize_t nread,
    const uv_buf_t *buf
) {
    ContextData *data = (ContextData *)client->data;
    MessageCache *ptrCache = &(data->peer->messageCache);
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) client, NULL);
        }
        else {
            // file ended; noop
        }
    } else {
        if (begins_with_header(buf->base)) {
            reset_message_cache(ptrCache);
            Header header = get_empty_header();
            parse_message_header((Byte *)buf->base, &header);
            ptrCache->expectedLength = sizeof(Header) + header.length;
        }
        memcpy(ptrCache->buffer + ptrCache->bufferIndex, buf->base, nread);
        ptrCache->bufferIndex += nread;

        if (ptrCache->bufferIndex == ptrCache->expectedLength) {
            Message message = get_empty_message();
            int32_t error = parse_buffer_into_message(ptrCache->buffer, &message);
            if (!error) {
                on_incoming_message(data->peer, message);
            }
            reset_message_cache(ptrCache);
        }
    }
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_peer_connect(uv_connect_t* req, int32_t status) {
    ContextData *data = (ContextData *)req->data;
    char *ipString = convert_ipv4_readable(data->peer->address.ip);
    if (status) {
        fprintf(
            stderr,
            "connection failed with peer %s: %s(%i) \n",
            ipString,
            uv_strerror(status),
            status
        );
        if (data->peer->relationship == REL_MY_SERVER) {
            disable_ip(data->peer->address.ip);
            connect_to_random_addr_for_peer(data->peer->index);
        }
    }
    else {
        printf("connected with peer %s \n", ipString);
        req->handle->data = req->data;
        send_message(req, CMD_VERSION);
        uv_read_start(req->handle, alloc_buffer, on_incoming_data);
    }
}

int32_t connect_to_address_as_peer(NetworkAddress addr, uint32_t peerIndex) {
    char *ipString = convert_ipv4_readable(addr.ip);
    printf("connecting with peer %s for peer %u\n", ipString, peerIndex);

    Peer *ptrPeer = &global.peers[peerIndex];

    ptrPeer->index = peerIndex;
    memcpy(ptrPeer->address.ip, addr.ip, sizeof(IP));
    ptrPeer->socket = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(uv_default_loop(), ptrPeer->socket);

    uv_connect_t* connection = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    ContextData *data = malloc(sizeof(ContextData)); //TODO: Free me somewhere
    memset(data, 0, sizeof(ContextData));
    data->peer = ptrPeer;
    connection->data = data;

    struct sockaddr_in remoteAddress = {0};
    uv_ip4_addr(ipString, htons(addr.port), &remoteAddress);
    uv_tcp_connect(
            connection,
            ptrPeer->socket,
            (const struct sockaddr*)&remoteAddress,
            &on_peer_connect
    );

    ptrPeer->connection = connection;
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
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_incoming_data);
    } else {
        printf("Cannot accept\n");
        uv_close((uv_handle_t*) client, NULL);
    }
}


int32_t setup_listen_socket() {
    printf("Setting up listen socket...");
    struct sockaddr_in localAddress = {0};
    uv_ip4_addr("0.0.0.0", parameters.port, &localAddress);
    uv_tcp_init(uv_default_loop(), &global.listenSocket);
    uv_tcp_bind(&global.listenSocket, (const struct sockaddr*) &localAddress, 0);
    int32_t listenError = uv_listen(
            (uv_stream_t*) &global.listenSocket,
            parameters.backlog,
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
    connect_to_address_as_peer(addr, peerIndex);
}

int32_t connect_to_initial_peers() {
    uint32_t outgoing = min(parameters.maxOutgoing, global.peerAddressCount);
    for (uint32_t i = 0; i < outgoing; i++) {
        connect_to_random_addr_for_peer(i);
        global.peerCount += 1;
    }
    return 0;
}

int32_t free_networking_resources() {
    printf("Freeing networking resources...");
    for (uint32_t peerIndex = 0; peerIndex < global.peerCount; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        if (peer->socket) {
//            uv_close(peer->connection->handle, on_close);
            free(peer->socket);
        }
    }
    uv_loop_close(uv_default_loop());
    printf("Done.\n");
    return 0;
}
