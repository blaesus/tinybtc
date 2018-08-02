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
#include "global_state.h"

int lookup_host(const char *host, char *ips[100]) {
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
        char addrstr[100];
        void *ptr;
        inet_ntop(response->ai_family, response->ai_addr->sa_data, addrstr, 100);

        if (response->ai_family == AF_INET6) {
            ptr = &((struct sockaddr_in6 *) response->ai_addr)->sin6_addr;
        }
        else {
            ptr = &((struct sockaddr_in *) response->ai_addr)->sin_addr;
        }
        inet_ntop(response->ai_family, ptr, addrstr, 100);
        ips[ip_index] = calloc(50, sizeof(char));
        strcpy(ips[ip_index], addrstr);
        ip_index += 1;
        response = response->ai_next;
    }

    return 0;
}

int dns_bootstrap() {
    const uint16_t array_length = sizeof(dns_seeds) / sizeof(char*);
    for (int i = 0; i < array_length; i++) {
        const char *seed = dns_seeds[i];
        char *ips[100] = { NULL };
        printf("Looking up %s\n", seed);
        lookup_host(seed, ips);

        for (int j = 0; j < sizeof(ips) / sizeof(char*); j++) {
            if (ips[j]) {
                printf("IP %i: %s\n", j, ips[j]);
                free(ips[j]);
            }
        }
    }
    return 0;
}

int main() {
    dns_bootstrap();
    return 0;
}
