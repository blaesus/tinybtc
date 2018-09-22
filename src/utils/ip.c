#include <stdbool.h>
#include <datatypes.h>
#include "utils/ip.h"

bool ips_equal(IP ipA, IP ipB) {
    return memcmp(ipA, ipB, sizeof(IP)) == 0;
}

