#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "uv/uv.h"

#define PEER_CONNECTION_TIMEOUT_SEC 5

uint32_t setup_main_event_loop();
int32_t setup_listen_socket(void);
int32_t connect_to_initial_peers(void);
int32_t free_networking_resources(void);
void connect_to_random_addr_for_peer(uint32_t peerIndex);
void send_message(
    uv_connect_t *req,
    char *command,
    void *data
);
