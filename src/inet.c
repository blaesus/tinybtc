#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "globalstate.h"
#include "inet.h"

uint32_t getV4BinaryIp(IP ip) {
    return (ip[15] << 3 * BYTE)
           + (ip[14] << 2 * BYTE)
           + (ip[13] << 1 * BYTE)
           + (ip[12]);
}

char *convert_ipv4_readable(IP ip) {
    // TODO: Handle ipv6
    struct in_addr addr = {
            .s_addr = getV4BinaryIp(ip)
    };
    return inet_ntoa(addr);
}

int print_ip(IP ip) {
    for (int i = 0; i < sizeof(IP) / sizeof(char); i++) {
        printf("%u", ip[i]);
        printf("-");
    }
    puts("\n");
    return 0;
}

int lookup_host(const char *host, IP ips[MAX_IP_PER_DNS]) {
    struct addrinfo hints, *response;
    int errcode;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo(host, NULL, &hints, &response);
    if (errcode != 0) {
        perror("getaddrinfo");
        return -1;
    }

    int ipIndex = 0;
    while (response) {
        IP ip = {0};
        if (response->ai_family == AF_INET6) {
            // TODO: ipv6 address parsing
            // struct in6_addr addr = ((struct sockaddr_in6 *) response->ai_addr)->sin6_addr;
        }
        else {
            uint32_t address = (((struct sockaddr_in *) response->ai_addr)->sin_addr).s_addr;
            ip[10] = (uint8_t)0xFF;
            ip[11] = (uint8_t)0xFF;
            ip[12] = (uint8_t)(address & 0xFF);
            ip[13] = (uint8_t)((address >> 1 * BYTE) & 0xFF);
            ip[14] = (uint8_t)((address >> 2 * BYTE) & 0xFF);
            ip[15] = (uint8_t)((address >> 3 * BYTE) & 0xFF);
        }
        memcpy(ips[ipIndex], ip, sizeof(IP));
        ipIndex += 1;
        response = response->ai_next;
    }

    return 0;
}

uint8_t dns_bootstrap() {
    puts("Bootstrapping peers via DNS");
    const uint16_t seedCount = sizeof(parameters.dns_seeds) / sizeof(DomainName);
    for (int seedIndex = 0; seedIndex < seedCount; seedIndex++) {
        DomainName seed;
        memcpy(seed, parameters.dns_seeds[seedIndex], sizeof(seed));
        IP ips[MAX_IP_PER_DNS] = { };
        printf("Looking up %s\n", seed);
        lookup_host(seed, ips);

        for (int ipIndex = 0; ipIndex < MAX_IP_PER_DNS; ipIndex++) {
            globalState.peerIpCount += 1;
            memcpy(globalState.peerIps[globalState.peerIpCount], ips[ipIndex], sizeof(IP));
        }
    }
    return 0;
}

int isIPEmpty(const IP ip) {
    for (int i = 0; i < 15; i++) {
        if (ip[i]) {
            return 0;
        }
    }
    return 1;
}

