#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "globalstate.h"
#include "inet.h"


uint32_t get_v4_binary_representation(const IP ip) {
    const uint32_t number = (ip[15] << 3 * BYTE)
                            + (ip[14] << 2 * BYTE)
                            + (ip[13] << 1 * BYTE)
                            + (ip[12]);
    return htonl(number);
}

char *convert_ipv4_readable(IP ip) {
    // TODO: Handle ipv6
    struct in_addr addr = {
        .s_addr = get_v4_binary_representation(ip)
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

int convert_ipv4_address_to_ip_array(uint32_t address, IP ip) {
    const uint32_t addressHostEndian = ntohl(address);
    ip[10] = (uint8_t)0xFF;
    ip[11] = (uint8_t)0xFF;
    ip[12] = (uint8_t)(addressHostEndian & 0xFF);
    ip[13] = (uint8_t)((addressHostEndian >> 1 * BYTE) & 0xFF);
    ip[14] = (uint8_t)((addressHostEndian >> 2 * BYTE) & 0xFF);
    ip[15] = (uint8_t)((addressHostEndian >> 3 * BYTE) & 0xFF);
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
        IP ips[MAX_IP_PER_DNS] = { };
        printf("Looking up %s\n", seed);
        lookup_host(seed, ips);

        for (int ipIndex = 0; ipIndex < MAX_IP_PER_DNS; ipIndex++) {
            if (!isIPEmpty(ips[ipIndex])) {
                add_peer(ips[ipIndex]);
            }
        }
    }
    return 0;
}

int add_loopback_peer() {
    puts("Adding loopback as peer");
    IP ip = {0};
    convert_ipv4_address_to_ip_array(inet_addr("127.0.0.1"), ip);
    add_peer(ip);
    return 0;
}

int setup_listen_socket() {
    struct addrinfo hints, *localAddress, *addr;
    int addrInfoError;
    int yes=1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((addrInfoError = getaddrinfo(NULL, "8333", &hints, &localAddress)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addrInfoError));
        return 1;
    }

    for(addr = localAddress; addr != NULL; addr = addr->ai_next) {
        globalState.listenSocket = socket(addr->ai_family, addr->ai_socktype,addr->ai_protocol);
        if (globalState.listenSocket < 0) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(globalState.listenSocket, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            perror("setsockopt");
            return 1;
        }

        int bindError = bind(globalState.listenSocket, addr->ai_addr, addr->ai_addrlen);
        if (bindError < 0) {
            fprintf(stderr, "Local binding failed with error code %u \n", errno);
            close(globalState.listenSocket);
            continue;
        }
        printf("Binding succeeded \n");

        break;
    }

    freeaddrinfo(localAddress); // all done with this structure
    if (addr == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 1;
    }

    const int listenError = listen(globalState.listenSocket, 10);
    if (listenError) {
        printf("Listening failed with error code %u \n", errno);
        return -1;
    }
    printf("Listening started\n");
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

int connect_to_peer(struct Peer *peer) {
    struct sockaddr_in remoteAddress = {0};
    peer->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (peer->socket < 0) {
        printf("Cannot create socket");
        return -1;
    }

    remoteAddress.sin_family = AF_INET;
    remoteAddress.sin_port = htons(parameters.port);
    remoteAddress.sin_addr.s_addr = get_v4_binary_representation(peer->ip);

//    long socketArgs = fcntl(peer->socket, F_GETFL, NULL);
//    socketArgs |= O_NONBLOCK;
//    fcntl(peer->socket, F_SETFL, socketArgs);

    char *ipString = convert_ipv4_readable(peer->ip);
    printf("Connecting socket to %s\n", ipString);
    const int connectError = connect(peer->socket, (struct sockaddr *)&remoteAddress, sizeof(remoteAddress));
    if (connectError < 0) {
        printf("Failed to connect to %s (%u) \n", ipString, errno);
        return -1;
    }
    printf("Connected to %s\n", ipString);

    return 0;
}

int establish_tcp_connections() {
    for (uint32_t peerIndex = 0; peerIndex < globalState.peerCount; peerIndex++) {
        struct Peer *peer = &globalState.peers[peerIndex];
        if (peer->active) {
            connect_to_peer(peer);
        }
    }
    return 0;
}


int close_tcp_connections() {
    printf("Closing connections");
    close(globalState.listenSocket);
    for (uint32_t peerIndex = 0; peerIndex < globalState.peerCount; peerIndex++) {
        struct Peer *peer = &globalState.peers[peerIndex];
        if (peer->socket) {
            close(peer->socket);
        }
    }
    return 0;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int monitor_incoming_messages() {
    puts("Setting up monitoring");
    int incomingSocket;
    struct sockaddr_in remoteAddress;
    socklen_t sin_size = sizeof remoteAddress;
    while(1) {  // main accept() loop
        sleep(1);
        puts("Accepting");
        printf("DEBUG %u, %u", globalState.listenSocket, sin_size);
        incomingSocket = accept(globalState.listenSocket, (struct sockaddr *)&remoteAddress, &sin_size);
        if (incomingSocket < 0) {
            perror("accept");
            continue;
        }
        puts("C");
        printf("server: got connection from \n");
        int childProcessId = fork();
        if (!childProcessId) { // child
            ssize_t sendError = send(incomingSocket, "Hello, world!", 13, 0);
            if (sendError < 0) {
                perror("send");
            }
            close(incomingSocket);
            return 0;
        }
        else { // parent
            printf("Process: I created child process %i\n", childProcessId);
            close(incomingSocket);  // parent doesn't need this
        }
    }
}

