#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "datatypes.h"
#include "util.h"

#define MAX_IP_PER_DNS 100

char *convert_ipv4_readable(IP ip);
int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]);
bool isIPEmpty(const IP ip);
int dns_bootstrap(void);
uint32_t get_v4_binary_representation(const IP ip);
int32_t get_local_listen_address(struct sockaddr_in *addr);
int convert_ipv4_address_to_ip_array(uint32_t address, IP ip);
