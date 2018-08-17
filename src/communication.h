#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "uv/uv.h"

uint32_t setup_main_event_loop(bool setupIdle);
int32_t setup_listen_socket(void);
int32_t connect_to_initial_peers(void);
int32_t free_networking_resources(void);
void send_message(
    uv_connect_t *req,
    char *command
);
