#include "util.h"
#include "cli.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int wcat_parse_port(const char *s)
{
    char *end = NULL;
    long value;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    errno = 0;
    value = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value < 1 || value > 65535) {
        return -1;
    }
    return (int)value;
}

int wcat_parse_timeout_ms(const char *s)
{
    char *end = NULL;
    long value;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    errno = 0;
    value = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value < 0 || value > INT_MAX / 1000) {
        return -1;
    }
    return (int)(value * 1000);
}

ssize_t wcat_full_write(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

int wcat_close_quiet(int fd)
{
    if (fd >= 0) {
        while (close(fd) < 0 && errno == EINTR) {
        }
    }
    return -1;
}

const char *wcat_mode_name(int mode)
{
    switch ((wcat_mode)mode) {
    case WCAT_MODE_CONNECT: return "connect";
    case WCAT_MODE_LISTEN: return "listen";
    case WCAT_MODE_SEND: return "send";
    case WCAT_MODE_RECV: return "recv";
    case WCAT_MODE_RELAY: return "relay";
    case WCAT_MODE_BROKER: return "broker";
    case WCAT_MODE_PROXY: return "proxy";
    case WCAT_MODE_NONE:
    default: return "none";
    }
}
