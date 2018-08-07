#pragma once

#include <stdint.h>
#include <stdbool.h>

uint32_t setup_main_event_loop(bool setupIdle);
int setup_listen_socket(void);
int setup_peer_connections(void);
int free_networking_resources(void);
