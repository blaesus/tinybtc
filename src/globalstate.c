#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "globalstate.h"
#include "util.h"
#include "networking.h"

GlobalState global;

void add_peer_address(NetworkAddress addr, uint32_t timestamp) {
    const uint32_t index = global.peerAddressCount;
    global.peerAddresses[index].timestamp = timestamp;
    memcpy(&global.peerAddresses[index].net_addr, &addr, sizeof(addr));

    global.peerAddressCount += 1;
}

void dedupe_global_addr_cache() {
    printf("Duplicating address cache...\n");
    struct AddrRecord buffer[MAX_ADDR_CACHE];
    memset(buffer, 0, sizeof(buffer));

    uint32_t newLength = 0;
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        Byte *ipAtIndex = global.peerAddresses[index].net_addr.ip;

        bool duplicated = false;
        for (uint32_t search = index+1; search < global.peerAddressCount; search++) {
            Byte *ipAtSearch = global.peerAddresses[search].net_addr.ip;
            if (ips_equal(ipAtSearch, ipAtIndex)) {
                duplicated = true;
                break;
            }
        }

        if (!duplicated) {
            memcpy(
                &buffer[newLength],
                &global.peerAddresses[index],
                sizeof(struct AddrRecord)
            );
            newLength++;
        }
    }
    printf("Deduplicated peer addresses: %u => %u\n", global.peerAddressCount, newLength);

    memcpy(&global.peerAddresses, &buffer, sizeof(buffer));
    global.peerAddressCount = newLength;
}

void clear_old_addr() {
    printf("Clearing up old address cache...\n");
    struct AddrRecord buffer[MAX_ADDR_CACHE];
    memset(buffer, 0, sizeof(buffer));

    uint32_t now = (uint32_t) time(NULL);

    uint32_t newLength = 0;
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        bool shouldRemove = (now - global.peerAddresses[index].timestamp > parameters.addrLife);

        if (!shouldRemove) {
            memcpy(
                &buffer[newLength],
                &global.peerAddresses[index],
                sizeof(struct AddrRecord)
            );
            newLength++;
        }
    }
    printf("Cleared old peer addresses: %u => %u\n", global.peerAddressCount, newLength);

    memcpy(&global.peerAddresses, &buffer, sizeof(buffer));
    global.peerAddressCount = newLength;
}

int32_t set_addr_timestamp(IP ip, uint32_t timestamp) {
    for (uint32_t index = 0; index < global.peerAddressCount; index++) {
        Byte *ipAtIndex = global.peerAddresses[index].net_addr.ip;
        if (ips_equal(ipAtIndex, ip)) {
            global.peerAddresses[index].timestamp = timestamp;
            char *ipString = convert_ipv4_readable(ip);
            printf("Updated timestamp of ip %s to %u\n", ipString, timestamp);
        }
    }
    return 0;
}
