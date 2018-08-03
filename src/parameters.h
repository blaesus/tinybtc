#pragma once

#include <stdint.h>
#include "inet.h"

struct Parameters {
    DomainName dns_seeds[6];
};

const struct Parameters parameters;
