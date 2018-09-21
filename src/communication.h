#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "libuv/include/uv.h"
#include "datatypes.h"
#include "parameters.h"

struct MessageCache {
    uint64_t bufferIndex;
    Byte buffer[MESSAGE_BUFFER_LENGTH];
};

typedef struct MessageCache MessageCache;

struct SocketContext {
    struct Peer *peer;
    MessageCache streamCache;
};

typedef struct SocketContext SocketContext;

struct ConnectContext {
    struct Peer *peer;
};

struct WriteContext {
    struct Peer *peer;
    uv_buf_t buf;
};

uint32_t setup_main_event_loop();
int32_t setup_listen_socket(void);
int32_t connect_to_initial_peers(void);
void connect_to_local(void);
int32_t release_sockets(void);
void terminate_sockets();
void connect_to_best_candidate_as_peer(uint32_t peerIndex);
void send_message(
    uv_tcp_t *socket,
    char *command,
    void *data
);
void terminate_execution();
