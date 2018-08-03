#pragma once

#include <stdint.h>

#define DOMAIN_NAME_LENGTH 50
#define MAX_IP_PER_DNS 100
#define BYTE 8

typedef uint8_t IP[16];
typedef char DomainName[DOMAIN_NAME_LENGTH];

char *convert_ipv4_readable(IP ip);
int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]);
int isIPEmpty(const IP ip);
uint8_t dns_bootstrap();
int establish_tcp_connections();
int close_tcp_connections();
