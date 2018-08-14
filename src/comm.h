#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "uv/uv.h"

uint32_t setup_main_event_loop(bool setupIdle);
int setup_listen_socket(void);
int connect_to_peers(void);
int free_networking_resources(void);
