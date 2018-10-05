#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <utils/memory.h>

#include "wallet.h"
#include "hash.h"
#include "parameters.h"
#include "utils/data.h"

#define CHECKSUM_WIDTH 4
#define VERSIONED_RIPEMD_WIDTH (RIPEMD_LENGTH+1)

void make_private_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, key);
    print_object(pkey, 256);
}

static const char* base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void binary_to_bn(Byte *data, uint64_t dataWidth, BIGNUM *num) {
    Byte *buffer = MALLOC(dataWidth, "setvch:buffer");
    memcpy(buffer, data, dataWidth);
    reverse_endian(buffer, dataWidth);
    BN_bin2bn(buffer, dataWidth, num);
    FREE(buffer, "setvch:buffer");
}

// adapted from: https://github.com/trezor/trezor-crypto/blob/master/base58.c

void binary_to_base58(const Byte *data, size_t dataWidth, char *base58)
{
    int32_t carry;
    ssize_t i, j, high, zeroCount = 0;
    size_t size;

    while (zeroCount < (ssize_t)dataWidth && !data[zeroCount]) {
        ++zeroCount;
    }

    size = (dataWidth - zeroCount) * 138 / 100 + 1;
    uint8_t *buffer = CALLOC(1, size, "binary_to_base58:buffer");

    for (i = zeroCount, high = size - 1; i < (ssize_t)dataWidth; ++i, high = j) {
        for (carry = data[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256 * buffer[j];
            buffer[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    for (j = 0; j < (ssize_t)size && !buffer[j]; ++j);

    if (zeroCount) {
        memset(base58, '1', zeroCount);
    }
    for (i = zeroCount; j < (ssize_t)size; ++i, ++j) {
        base58[i] = base58Alphabet[buffer[j]];
    }
    base58[i] = '\0';
    FREE(buffer, "binary_to_base58:buffer");
}


void private_key_to_wip(Byte *pubkey, char *address) {
    RIPEMD_HASH ripe = {0};
    sharipe(pubkey, 33, ripe);
    Byte versionedRipe[VERSIONED_RIPEMD_WIDTH] = {0};
    versionedRipe[0] = mainnet.addressVersion;
    memcpy(versionedRipe+1, ripe, sizeof(ripe));
    SHA256_HASH checksumHash = {0};
    dsha256(versionedRipe, VERSIONED_RIPEMD_WIDTH, checksumHash);

    Byte finalHash[VERSIONED_RIPEMD_WIDTH+CHECKSUM_WIDTH] = {0};
    memcpy(finalHash, versionedRipe, VERSIONED_RIPEMD_WIDTH);
    memcpy(finalHash+VERSIONED_RIPEMD_WIDTH, checksumHash, CHECKSUM_WIDTH);

    print_object(finalHash, VERSIONED_RIPEMD_WIDTH+CHECKSUM_WIDTH);

    binary_to_base58(finalHash, VERSIONED_RIPEMD_WIDTH + CHECKSUM_WIDTH, address);
}
