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
    if (global.eventCounter >= 1e7) {
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

void on_incoming_message(
        uv_stream_t *client,
        ssize_t nread,
        const uv_buf_t *buf
) {
    printf("\n>----------------------------------------------------------");
    printf("\nIncoming message");
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) client, NULL);
        }
    } else if (nread > 0) {
        struct Message incomingMessage = {0};
        parseMessageHeader(buf->base, &incomingMessage);
        if (incomingMessage.magic == parameters.magic) {
            printObjectWithLength(buf->base, nread);
            printf("Message parsed: MAGIC=%x, COMMAND=%s, LENGTH=%u\n",
                   incomingMessage.magic,
                   incomingMessage.command,
                   incomingMessage.length
            );
        }
        else {
            printf("\nMAGIC mismatch: %x != %x\n", parameters.magic, incomingMessage.magic);
        }
        printf("----------------------------------------------------------<\n");
    }

    if (buf->base) {
        free(buf->base);
    }
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}


void on_version_sent(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, " [ERR] failed to send version: %s \n", uv_strerror(status));
        return;
    }
    else {
        printf("\nversion sent\n");
    }
}

void send_version(struct Peer *ptrPeer, uv_connect_t* req) {
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

    char *ipString = convert_ipv4_readable(ptrPeer->address.ip);
    printf("\nSending version message to peer %s\n", ipString);
    printObjectWithLength(buffer, dataSize);

    uvBuffer.len = dataSize;
    uvBuffer.base = (char *)buffer;

    uv_stream_t* tcp = req->handle;
    uv_write_t write_req;
    uint8_t bufferCount = 1;
    uv_write(&write_req, tcp, &uvBuffer, bufferCount, &on_version_sent);
}

void on_peer_connect(uv_connect_t* req, int32_t status) {
    struct ContextData *data = (struct ContextData *)req->data;
    char *ipString = convert_ipv4_readable(data->peer->address.ip);
    if (status) {
        fprintf(stderr, " [ERR] connection failed with peer %s: %s \n", ipString, uv_strerror(status));
    }
    else {
        printf(" [OK]  connected with peer %s \n", ipString);
        struct Peer *ptrPeer = ((struct ContextData *)(req->data))->peer;
        send_version(ptrPeer, req);
        uv_read_start(req->handle, alloc_buffer, on_incoming_message);
    }
}


int32_t connect_to_peer(struct Peer *ptrPeer) {
    char *ipString = convert_ipv4_readable(ptrPeer->address.ip);
    printf(" > connecting with peer %s\n", ipString);
    struct sockaddr_in remoteAddress = {0};
    ptrPeer->socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_connect_t* connection = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    struct ContextData *data = malloc(sizeof(struct ContextData)); //TODO: Free me somewhere
    data->peer = ptrPeer;
    connection->data = data;
    uv_tcp_init(uv_default_loop(), ptrPeer->socket);
    uv_ip4_addr(ipString, parameters.port, &remoteAddress);
    uv_tcp_connect(connection, ptrPeer->socket, (const struct sockaddr*)&remoteAddress, &on_peer_connect);
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
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_incoming_message);
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

    uint32_t maxConnection = min(parameters.maxOutgoing, global.peerCount);
    // TODO: randomize properly
    uint32_t OFFSET = (uint32_t)((random_uint64() % maxConnection) % 0xFFFFFFFF);

    printf("Connecting to %u peers\n", maxConnection);
    for (uint32_t peerIndex = OFFSET; peerIndex < maxConnection + OFFSET; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        if (peer->valid) {
            connect_to_peer(peer);
        }
    }
    return 0;
}

int32_t free_networking_resources() {
    printf("Freeing networking resources...");
    for (uint32_t peerIndex = 0; peerIndex < global.peerCount; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        if (peer->socket) {
            free(peer->socket);
        }
    }
    uv_loop_close(uv_default_loop());
    printf("Done.\n");
    return 0;
}
