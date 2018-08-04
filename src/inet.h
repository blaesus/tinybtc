#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#define DOMAIN_NAME_LENGTH 50
#define MAX_IP_PER_DNS 100
#define BYTE 8

typedef uint8_t IP[16];
typedef char DomainName[DOMAIN_NAME_LENGTH];

char *convert_ipv4_readable(IP ip);
int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]);
bool isIPEmpty(const IP ip);
int dns_bootstrap(void);
int add_loopback_peer(void);
int setup_listen_socket(void);
int establish_tcp_connections(void);
int close_tcp_connections(void);
int monitor_incoming_messages(void);
