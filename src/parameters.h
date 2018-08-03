#pragma once

typedef char IP[16];
typedef char IPAddressString[100];
typedef char DomainName[50];

struct Parameters {
    DomainName dns_seeds[6];
};

const struct Parameters parameters;
