#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <pthread.h>

#include "globalstate.h"
#include "networking.h"
#include "util.h"



uint32_t get_v4_binary_representation(const IP ip) {
    const uint32_t number = (ip[12] << 3 * BITS_IN_BYTE)
                            + (ip[13] << 2 * BITS_IN_BYTE)
                            + (ip[14] << 1 * BITS_IN_BYTE)
                            + (ip[15]);
    return htonl(number);
}

char *convert_ipv4_readable(IP ip) {
    struct in_addr addr = {
        .s_addr = get_v4_binary_representation(ip)
    };
    return inet_ntoa(addr);
}

int print_ip(IP ip) {
    for (size_t i = 0; i < sizeof(IP) / sizeof(char); i++) {
        printf("%u", ip[i]);
        printf("-");
    }
    puts("\n");
    return 0;
}

int convert_ipv4_address_to_ip_array(uint32_t address, IP ip) {
    if (!address) {
        return 0;
    }
    ip[10] = (uint8_t)0xFF;
    ip[11] = (uint8_t)0xFF;
    ip[15] = (uint8_t)((address >> 3 * BITS_IN_BYTE) & 0xFF);
    ip[14] = (uint8_t)((address >> 2 * BITS_IN_BYTE) & 0xFF);
    ip[13] = (uint8_t)((address >> 1 * BITS_IN_BYTE) & 0xFF);
    ip[12] = (uint8_t)(address & 0xFF);
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
            convert_ipv4_address_to_ip_array(address, ip);
        }
        memcpy(ips[ipIndex], ip, sizeof(IP));
        ipIndex += 1;
        response = response->ai_next;
    }

    return 0;
}

int dns_bootstrap() {
    puts("Bootstrapping peers via DNS");
    const uint16_t seedCount = sizeof(parameters.dnsSeeds) / sizeof(DomainName);
    for (int seedIndex = 0; seedIndex < seedCount; seedIndex++) {
        DomainName seed;
        memcpy(seed, parameters.dnsSeeds[seedIndex], sizeof(seed));
        IP ips[MAX_IP_PER_DNS] = {{0}};
        printf("Looking up %s\n", seed);
        lookup_host(seed, ips);

        for (int ipIndex = 0; ipIndex < MAX_IP_PER_DNS; ipIndex++) {
            if (!isIPEmpty(ips[ipIndex])) {
                add_peer_address(ips[ipIndex]);
                printf("%s\n", convert_ipv4_readable(ips[ipIndex]));
            }
        }
    }
    return 0;
}

int32_t get_local_listen_address(struct sockaddr_in *addr) {
    struct addrinfo hints, *localAddress;
    int32_t addrInfoError;
    char port[5] = {0};

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // Use my IP

    uint_to_str(parameters.port, port);

    if ((addrInfoError = getaddrinfo(NULL, port, &hints, &localAddress)) != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(addrInfoError));
        return 1;
    }
    memcpy(addr, (struct sockaddr_in *)localAddress->ai_addr, sizeof(struct sockaddr_in *));
    return 0;
}

bool isIPEmpty(const IP ip) {
    for (int i = 0; i < 15; i++) {
        if (ip[i]) {
            return false;
        }
    }
    return true;
}

bool is_ipv4(IP ip) {
    return (
        ip[0] == 0 &&
        ip[1] == 0 &&
        ip[2] == 0 &&
        ip[3] == 0 &&
        ip[4] == 0 &&
        ip[5] == 0 &&
        ip[6] == 0 &&
        ip[7] == 0 &&
        ip[8] == 0 &&
        ip[9] == 0 &&
        ip[10] == (uint8_t)0xFF &&
        ip[11] == (uint8_t)0xFF
    );
}
