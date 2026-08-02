#ifndef WCAT_UTIL_H
#define WCAT_UTIL_H

#include <stddef.h>
#include <sys/types.h>

int wcat_parse_port(const char *s);
int wcat_parse_timeout_ms(const char *s);
ssize_t wcat_full_write(int fd, const void *buf, size_t len);
int wcat_close_quiet(int fd);
const char *wcat_mode_name(int mode);

#endif

