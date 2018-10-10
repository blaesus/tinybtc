#include "openssl/bn.h"
#include "datatypes.h"
#include "utils/data.h"
#include "utils/memory.h"

uint32_t bignum_to_bytes(BIGNUM* num, Byte *buffer) {
    int32_t width = BN_bn2mpi(num, NULL);
    if (width < 4) {
        return 0;
    }
    BN_bn2mpi(num, buffer);
    memcpy(buffer, buffer+3, width);
    width -= 3;
    reverse_bytes(buffer, (uint32_t)width);
    // FIXME: Hack
    // Check tx 61a078472543e9de9247446076320499c108b52307d8d0fafbe53b5c4e32acc4
    // This function produces [0x14, 0x01] for (OP_NEGATE [0x14])
    // But actually the function expects [0x94]
    // if (buffer[1] == 1) {
    //     buffer[1] = 0;
    //     buffer[0] += 0x80;
    //     width--;
    // }
    return (uint32_t)width;
}

void bytes_to_bignum(Byte *buffer, uint32_t width, BIGNUM* num) {
    Byte *data = CALLOC(1, width+3, "bytes_to_bignum:data");
    data[0] = (Byte)((width >> 24) & 0xff);
    data[1] = (Byte)((width >> 16) & 0xff);
    data[2] = (Byte)((width >> 8) & 0xff);
    data[3] = (Byte)((width >> 0) & 0xff);
    memcpy(data + 3, buffer, width);
    reverse_bytes(data + 3, width);
    BN_mpi2bn(data, width+3, num);
    FREE(data, "bytes_to_bignum:data");
}

