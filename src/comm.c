#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "uv.h"

#include "globalstate.h"
#include "inet.h"
#include "message.h"

void on_idle(uv_idle_t *handle) {
    global.eventCounter++;
    if (global.eventCounter % 1000000 == 0) {
        printf("Event count %llu\n", global.eventCounter);
    }
    if (global.eventCounter >= 1e8) {
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

char *get_peer_ip(uv_connect_t *req) {
    struct ContextData *data = (struct ContextData *)req->data;
    return convert_ipv4_readable(data->peer->address.ip);
}

uint64_t load_version_payload(
    uint8_t *ptrBuffer,
    Message *ptrMessage
) {
    VersionPayload payload = {0};
    const uint64_t payloadOffset = parse_version_payload(ptrBuffer, &payload);
    ptrMessage->payload = malloc(sizeof(VersionPayload)); //FIXME: Free
    memcpy(ptrMessage->payload, &payload, sizeof(VersionPayload));
    return payloadOffset;
}

uint64_t load_payload(
        uint8_t *ptrBuffer,
        uint8_t *command,
        Message *ptrMessage
) {
    if (strcmp((char *)command, "version") == 0) {
        return load_version_payload(ptrBuffer, ptrMessage);
    }
    else if (strcmp((char *)command, "verack") == 0) {
        return 0;
    }
    else {
        fprintf(stderr, "Cannot load payload for COMMAND %s\n", command);
        return 0;
    }
}

void print_message_header(Message *ptrMessage) {
    printf("\nheader: MAGIC=%x, COMMAND=%s, LENGTH=%u\n",
           ptrMessage->magic,
           ptrMessage->command,
           ptrMessage->length
    );
}

void print_message_payload(
        uint8_t *command,
        Payload *ptrPayload
) {
    if (strcmp((char *)command, "version") == 0) {
        VersionPayload *ptrPayloadTyped = (VersionPayload *)ptrPayload;
        printf("payload: version=%u, user_agent=%s\n",
               ptrPayloadTyped->version,
               ptrPayloadTyped->user_agent.string
        );
    }
    else if (strcmp((char *)command, "verack") == 0) {
        printf("(verack payload is empty)\n");
    }
    else {
        fprintf(stderr, "Cannot print payload for COMMAND %s\n", command);
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

void send_verack(uv_connect_t *req) {
    struct Message message = {0};
    make_verack_message(&message);

    uint8_t buffer[MESSAGE_BUFFER_SIZE] = {0};
    uv_buf_t uvBuffer = uv_buf_init((char *)buffer, sizeof(buffer));

    uint64_t dataSize = serialize_verack_message(
            &message,
            buffer,
            MESSAGE_BUFFER_SIZE
    );

    char *ipString = get_peer_ip(req);
    printf("Sending verack message to peer %s\n", ipString);

    uvBuffer.len = dataSize;
    uvBuffer.base = (char *)buffer;

    uv_stream_t* tcp = req->handle;
    uv_write_t write_req;
    uint8_t bufferCount = 1;
    write_req.data = req->data;
    uv_write(&write_req, tcp, &uvBuffer, bufferCount, &on_message_sent);
}


void print_message_cache(MessageCache messageCache) {
    printf("\n>====== Incoming ========");
    print_message_header(messageCache.message);
    print_message_payload(
            messageCache.message->command,
            messageCache.message->payload
    );
    printf("========================<\n");
}

void on_incoming_message(Peer *ptrPeer) {
    print_message_cache(ptrPeer->messageCache);

    Byte *command = ptrPeer->messageCache.message->command;

    if (strcmp((char *)command, "version") == 0) {
        VersionPayload *ptrPayloadTyped = (VersionPayload *)ptrPeer->messageCache.message->payload;
        if (ptrPayloadTyped->version >= parameters.minimalPeerVersion) {
            ptrPeer->handshake.acceptThem = true;
        }
    }
    else if (strcmp((char *)command, "verack") == 0) {
        ptrPeer->handshake.acceptUs = true;
        send_verack(ptrPeer->connection);
    }

    ptrPeer->messageCache.headerLoaded = false;
    ptrPeer->messageCache.payloadLoaded = false;
}

void on_incoming_data(
        uv_stream_t *client,
        ssize_t nread,
        const uv_buf_t *buf
) {
    struct ContextData *data = (struct ContextData *)client->data;
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) client, NULL);
        }
    } else {
        if (begins_width_header(buf->base)) {
            struct Message message = {0};
            parse_message_header((Byte *)buf->base, &message);

            if (data->peer->messageCache.message) {
                free(data->peer->messageCache.message);
                data->peer->messageCache.message = NULL;
            }
            data->peer->messageCache.message = malloc(sizeof(Message));
            uint32_t headerWidth = sizeof(MessageHeader);
            memcpy(data->peer->messageCache.message, &message, headerWidth);
            data->peer->messageCache.headerLoaded = true;
            data->peer->messageCache.payloadLoaded = false;

            bool payloadIncluded = nread - headerWidth == message.length;
            if (payloadIncluded) {
                load_payload(
                        (Byte *)buf->base+headerWidth,
                        message.command,
                        data->peer->messageCache.message
                );
                data->peer->messageCache.payloadLoaded = true;
            }
        } else if (data->peer->messageCache.headerLoaded) {
            load_payload(
                    (Byte *)buf->base,
                    data->peer->messageCache.message->command,
                    data->peer->messageCache.message
            );
            data->peer->messageCache.payloadLoaded = true;
        }
        else {
            printf("\nUnexpected data");
            print_object(buf->base, nread);
        }
    }

    if (data->peer->messageCache.headerLoaded && data->peer->messageCache.payloadLoaded) {
        on_incoming_message(data->peer);
    }
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void send_version(uv_connect_t *req) {
    struct Peer *ptrPeer = ((struct ContextData *)(req->data))->peer;
    struct VersionPayload payload = {0};
    uint32_t payloadLength = make_version_payload_to_peer(ptrPeer, &payload);

    struct Message message = {0};
    make_version_message(&message, &payload, payloadLength);

    uint8_t buffer[MESSAGE_BUFFER_SIZE] = {0};
    uv_buf_t uvBuffer = uv_buf_init((char *)buffer, sizeof(buffer));

    uint64_t dataSize = serialize_version_message(
            &message,
            buffer,
            MESSAGE_BUFFER_SIZE
    );

    char *ipString = get_peer_ip(req);
    printf("Sending version message to peer %s\n", ipString);

    uvBuffer.len = dataSize;
    uvBuffer.base = (char *)buffer;

    uv_stream_t* tcp = req->handle;
    uv_write_t write_req;
    uint8_t bufferCount = 1;
    write_req.data = req->data;
    uv_write(&write_req, tcp, &uvBuffer, bufferCount, &on_message_sent);
}

void on_peer_connect(uv_connect_t* req, int32_t status) {
    struct ContextData *data = (struct ContextData *)req->data;
    char *ipString = convert_ipv4_readable(data->peer->address.ip);
    if (status) {
        fprintf(stderr, "connection failed with peer %s: %s \n", ipString, uv_strerror(status));
    }
    else {
        printf("connected with peer %s \n", ipString);
        req->handle->data = req->data;
        send_version(req);
        uv_read_start(req->handle, alloc_buffer, on_incoming_data);
    }
}

int32_t connect_to_peer_address(IP ip) {
    char *ipString = convert_ipv4_readable(ip);
    printf(" > connecting with peer %s as peer %u\n", ipString, global.peerCount);

    Peer *ptrPeer = &global.peers[global.peerCount];
    global.peerCount += 1;

    memcpy(ptrPeer->address.ip, ip, sizeof(IP));
    ptrPeer->socket = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(uv_default_loop(), ptrPeer->socket);

    uv_connect_t* connection = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    struct ContextData *data = malloc(sizeof(struct ContextData)); //TODO: Free me somewhere
    memset(data, 0, sizeof(struct ContextData));
    data->peer = ptrPeer;
    connection->data = data;

    struct sockaddr_in remoteAddress = {0};
    uv_ip4_addr(ipString, parameters.port, &remoteAddress);
    uv_tcp_connect(
            connection,
            ptrPeer->socket,
            (const struct sockaddr*)&remoteAddress,
            &on_peer_connect
    );

    ptrPeer->connection = connection;
    return 0;
}

void on_echo_write_finish(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free(req);
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

int32_t connect_to_peers() {
    uint32_t maxConnection = min(parameters.maxOutgoing, global.peerAddressCount);
    printf("Connecting to %u peers\n", maxConnection);
    // TODO: randomize properly
    uint32_t OFFSET = (uint32_t)((random_uint64() % maxConnection) % 0xFFFFFFFF);
    for (uint32_t peerIndex = OFFSET; peerIndex < maxConnection + OFFSET; peerIndex++) {
        IP ip = {0};
        memcpy(ip, global.peerAddresses[peerIndex], sizeof(ip));
        connect_to_peer_address(ip);
    }
    return 0;
}

void on_close() {
    printf("Closed!");
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
