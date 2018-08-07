#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "uv.h"

#include "globalstate.h"
#include "inet.h"

void on_idle(uv_idle_t *handle) {
    global.eventCounter++;
    if (global.eventCounter % 1000000 == 0) {
        printf("Event count %u\n", global.eventCounter);
    }
    if (global.eventCounter >= 1e7) {
        uv_idle_stop(handle);
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
};

struct ContextData {
    struct Peer *peer;
};

void on_peer_connect(uv_connect_t* req, int32_t status) {
    struct ContextData *data = (struct ContextData *)req->data;
    char *ipString = convert_ipv4_readable(data->peer->address.ip);
    if (status) {
        fprintf(stderr, " [ERR] connection failed with peer %s: %s \n", ipString, uv_strerror(status));
    }
    else {
        printf(" [OK]  connected with peer %s \n", ipString);
    }
}


int32_t connect_to_peer(struct Peer *peer) {
    char *ipString = convert_ipv4_readable(peer->address.ip);
    printf(" > connecting with peer %s\n", ipString);
    struct sockaddr_in remoteAddress = {0};
    peer->socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_connect_t* connection = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    struct ContextData *data = malloc(sizeof(struct ContextData)); //TODO: Free me somewhere
    data->peer = peer;
    connection->data = data;
    uv_tcp_init(uv_default_loop(), peer->socket);
    uv_ip4_addr(ipString, parameters.port, &remoteAddress);
    uv_tcp_connect(connection, peer->socket, (const struct sockaddr*)&remoteAddress, &on_peer_connect);
    return 0;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_echo_write_finish(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free(req);
}

void on_incoming_message(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) client, NULL);
        }
    } else if (nread > 0) {
        uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
        uv_buf_t wrbuf = uv_buf_init(buf->base, (unsigned int)nread);
        uv_write(req, client, &wrbuf, 1, on_echo_write_finish);
    }

    if (buf->base) {
        free(buf->base);
    }
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

int32_t setup_peer_connections() {
    printf("Setting up peers\n");
    for (uint32_t peerIndex = 0; peerIndex < global.peerCount; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        if (peer->valid) {
            connect_to_peer(peer);
        }
    }
    return 0;
}

int32_t free_networking_resources() {
    printf("Freeing networking resources");
    for (uint32_t peerIndex = 0; peerIndex < global.peerCount; peerIndex++) {
        struct Peer *peer = &global.peers[peerIndex];
        if (peer->socket) {
            free(peer->socket);
        }
    }
    uv_loop_close(uv_default_loop());
    return 0;
}
