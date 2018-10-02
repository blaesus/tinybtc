#include <stdint.h>
#include "datatypes.h"
#include "utils/data.h"

void reverse_endian(Byte *data, uint32_t width) {
    for (uint32_t i = 0; i < width / 2; i++) {
        Byte temp = data[i];
        data[i] = data[width - i - 1];
        data[width - i - 1] = temp;
    }
}

void print_object(void *ptrData, uint64_t length) {
    uint64_t index;
    uint8_t character = 0;
    Byte *p = ptrData;
    for (index = 0; index < length; index++) {
        character = (uint8_t)(*p & 0xFF);
        if (index % 16 == 0) {
            printf("\n%03llx0 - ", index / 16);
        }
        printf("%02x ", character);
        p++;
    }
    printf("END \n");
}

int8_t bytescmp(const Byte *bytesA, const Byte *bytesB, uint32_t width) {
    for (uint32_t i = width - 1; i > 0; i--) {
        if (bytesA[i] < bytesB[i]) {
            return -1;
        }
        if (bytesA[i] > bytesB[i]) {
            return 1;
        }
    }
    return 0;
}

bool is_byte_array_empty(const Byte *hash, uint64_t length) {
    for (uint64_t i = 0; i < length; i++) {
        if (hash[i]) {
            return false;
        }
    }
    return true;
}
