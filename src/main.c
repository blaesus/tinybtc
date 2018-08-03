//
// Created by Andy Shu on 30/7/2018.
//

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "Block.h"
#include "parameters.h"
#include "globalstate.h"

int lookup_host(const char *host, IPAddressString ips[100]) {
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

    int ip_index = 0;
    while (response) {
        IPAddressString ipAddressString;
        void *ptr;
        inet_ntop(response->ai_family, response->ai_addr->sa_data, ipAddressString, 100);

        if (response->ai_family == AF_INET6) {
            ptr = &((struct sockaddr_in6 *) response->ai_addr)->sin6_addr;
        }
        else {
            ptr = &((struct sockaddr_in *) response->ai_addr)->sin_addr;
        }
        inet_ntop(response->ai_family, ptr, ipAddressString, 100);
        strcpy(ips[ip_index], ipAddressString);
        ip_index += 1;
        response = response->ai_next;
    }

    return 0;
}

uint8_t dns_bootstrap() {
    const uint16_t seed_array_length = sizeof(parameters.dns_seeds) / sizeof(DomainName);
    for (int i = 0; i < seed_array_length; i++) {
        DomainName seed;
        strcpy(seed, parameters.dns_seeds[i]);
        IPAddressString ipStrings[100] = { };
        printf("Looking up %s\n", seed);
        lookup_host(seed, ipStrings);

        for (int j = 0; j < sizeof(ipStrings) / sizeof(IPAddressString); j++) {
            if (ipStrings[j][0] != '\0') {
                globalState.peerIpIndex += 1;
                strcpy(globalState.peerIps[globalState.peerIpIndex], ipStrings[j]);
                printf("IP %i: %s\n", j, ipStrings[j]);
            }
        }
    }
    return 0;
}

int checkGlobalState() {
    for (int i = 0; i < sizeof(globalState.peerIps) / sizeof(IPAddressString); i++) {
        if (globalState.peerIps[i][0] != '\0') {
            printf("%s\n", globalState.peerIps[i]);
        }
    }
}

int main() {
    dns_bootstrap();
    checkGlobalState();
    return 0;
}
