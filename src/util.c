#include <stdio.h>
#include <util.h>


int segment_int32(uint32_t number, uint8_t chars[4]) {
    chars[0] = (uint8_t)(number & 0xFF);
    chars[1] = (uint8_t)((number >> 1 * BYTE) & 0xFF);
    chars[2] = (uint8_t)((number >> 2 * BYTE) & 0xFF);
    chars[3] = (uint8_t)((number >> 3 * BYTE) & 0xFF);
    return 0;
}

uint32_t combine_int32(uint8_t chars[4]) {
    uint32_t number = (chars[3] << 3 * BYTE)
                      + (chars[2] << 2 * BYTE)
                      + (chars[1] << 1 * BYTE)
                      + (chars[0]);
    return number;
}

uint32_t count_string_length(char *s) {
    uint32_t i;
    for (i = 0; s[i] != '\0'; i++);
    return i+1;
}

void swap(char *a, char *b) {
    char temp = *b;
    *b = *a;
    *a = temp;
}

void reverse_string(char *s) {
    uint32_t length = count_string_length(s);
    for (uint32_t i = 0; i < length / 2; i++) {
        swap(&s[i], &s[length - i - 2]);
    }
}

int32_t uint_to_str(uint32_t data, char *output) {
    uint32_t i;
    for (i = 0; data > 0; i++) {
        uint32_t digit = data % 10;
        output[i] = (char)(digit + '0');
        data /= 10;
    }
    output[i] = '\0';
    reverse_string(output);
    return 0;
}
