#include <sys/time.h>
#include "utils/datetime.h"

char *date_string(time_t time) {
    static char text[100];
    struct tm *timeInfo = localtime(&time);
    strftime(text, sizeof(text)-1, "%Y-%m-%d %H:%M:%S", timeInfo);
    return text;
}

static double timeval_to_double_ms(struct timeval time) {
    return 1.0 * time.tv_sec * 1000 + 1.0 * time.tv_usec / 1000;
}

double get_now() {
    struct timeval nowTimeval;
    gettimeofday(&nowTimeval, NULL);
    return timeval_to_double_ms(nowTimeval);
}

