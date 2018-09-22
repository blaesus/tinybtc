#include "stdint.h"
#include "utils/strings.h"

uint32_t count_string_length(const char *s) {
    uint32_t i;
    for (i = 0; s[i] != '\0'; i++);
    return i+1;
}

void swap_char(char *a, char *b) {
    char temp = *b;
    *b = *a;
    *a = temp;
}

void reverse_string(char *s) {
    uint32_t length = count_string_length(s);
    for (uint32_t i = 0; i < length / 2; i++) {
        swap_char(&s[i], &s[length - i - 2]);
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

