#ifndef WCAT_LOG_H
#define WCAT_LOG_H

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    WCAT_LOG_ERROR = 0,
    WCAT_LOG_WARN,
    WCAT_LOG_INFO,
    WCAT_LOG_DEBUG
} wcat_log_level;

void wcat_log_init(bool json, bool verbose);
void wcat_log(wcat_log_level level, const char *event, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void wcat_log_errno(const char *event, const char *context);
void wcat_hexdump(const char *label, const unsigned char *buf, size_t len);

#endif

