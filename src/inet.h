#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "util.h"

#define DOMAIN_NAME_LENGTH 50
#define MAX_IP_PER_DNS 100

typedef uint8_t IP[16];
typedef char DomainName[DOMAIN_NAME_LENGTH];

char *convert_ipv4_readable(IP ip);
int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]);
bool isIPEmpty(const IP ip);
int dns_bootstrap(void);
uint32_t get_v4_binary_representation(const IP ip);
int32_t get_local_listen_address(struct sockaddr_in *addr);
