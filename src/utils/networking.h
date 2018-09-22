#pragma once

#include "datatypes.h"

#define MAX_IP_PER_DNS 100
#define DNS_BOOTSTRAP_PEER_TIMESTAMP 0

char *convert_ipv4_readable(IP ip);
int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]);
bool isIPEmpty(const IP ip);
int dns_bootstrap(void);
uint32_t get_v4_binary_representation(const IP ip);
int32_t get_local_listen_address(struct sockaddr_in *addr);
int convert_ipv4_address_to_ip_array(uint32_t address, IP ip);

bool is_ipv4(IP ip);
bool ips_equal(IP ipA, IP ipB);
