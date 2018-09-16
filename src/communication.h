#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "libuv/include/uv.h"
#include "datatypes.h"
#include "parameters.h"

#define PEER_CONNECTION_TIMEOUT_SEC 5

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
    char *ptrBufferBase;
};

uint32_t setup_main_event_loop();
int32_t setup_listen_socket(void);
int32_t connect_to_initial_peers(void);
void connect_to_local(void);
int32_t release_sockets(void);
void connect_to_random_addr_for_peer(uint32_t peerIndex);
void send_message(
    uv_tcp_t *socket,
    char *command,
    void *data
);
