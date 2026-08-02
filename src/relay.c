#include "relay.h"
#include "log.h"
#include "signalx.h"
#include "util.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#define WCAT_BUFSIZE 16384

static ssize_t fd_read(void *ctx, void *buf, size_t len)
{
    wcat_stream *s = ctx;
    return read(s->raw_fd, buf, len);
}

static ssize_t fd_write(void *ctx, const void *buf, size_t len)
{
    wcat_stream *s = ctx;
    return wcat_full_write(s->write_fd, buf, len);
}

static int fd_get(void *ctx)
{
    wcat_stream *s = ctx;
    return s->raw_fd;
}

static int fd_shutdown_write(void *ctx)
{
    wcat_stream *s = ctx;

    if (!s->can_close_write || s->write_fd < 0) {
        return 0;
    }
    if (s->write_fd == s->raw_fd) {
        if (shutdown(s->write_fd, SHUT_WR) == 0 || errno == ENOTSOCK) {
            return 0;
        }
        return -1;
    }
    (void)wcat_close_quiet(s->write_fd);
    s->write_fd = -1;
    return 0;
}

static ssize_t tls_read_wrap(void *ctx, void *buf, size_t len)
{
    return wcat_tls_read(ctx, buf, len);
}

static ssize_t tls_write_wrap(void *ctx, const void *buf, size_t len)
{
    return wcat_tls_write(ctx, buf, len);
}

static int tls_fd_wrap(void *ctx)
{
    wcat_tls_stream *s = ctx;
    return s->fd;
}

static int tls_pending_wrap(void *ctx)
{
    return wcat_tls_pending(ctx);
}

static int tls_tick_wrap(void *ctx)
{
    return wcat_tls_tick(ctx);
}

static int tls_shutdown_write_wrap(void *ctx)
{
    return wcat_tls_shutdown_write(ctx);
}

void wcat_stream_from_fd(wcat_stream *s, int fd, const char *name)
{
    memset(s, 0, sizeof(*s));
    s->raw_fd = fd;
    s->write_fd = fd;
    s->ctx = s;
    s->read = fd_read;
    s->write = fd_write;
    s->fd = fd_get;
    s->shutdown_write = fd_shutdown_write;
    s->name = name;
    s->can_close_write = 1;
    s->close_on_eof = 1;
}

void wcat_stream_from_fd_pair(wcat_stream *s, int read_fd, int write_fd, const char *name)
{
    memset(s, 0, sizeof(*s));
    s->raw_fd = read_fd;
    s->write_fd = write_fd;
    s->ctx = s;
    s->read = fd_read;
    s->write = fd_write;
    s->fd = fd_get;
    s->shutdown_write = fd_shutdown_write;
    s->name = name;
    s->can_close_write = write_fd != STDOUT_FILENO;
    s->close_on_eof = read_fd != STDIN_FILENO;
}

void wcat_stream_from_tls(wcat_stream *s, wcat_tls_stream *tls, const char *name)
{
    memset(s, 0, sizeof(*s));
    s->ctx = tls;
    s->read = tls_read_wrap;
    s->write = tls_write_wrap;
    s->fd = tls_fd_wrap;
    s->shutdown_write = tls_shutdown_write_wrap;
    s->pending = tls_pending_wrap;
    s->tick = tls_tick_wrap;
    s->name = name;
    s->close_on_eof = 1;
}

static int stream_tick(wcat_stream *s)
{
    if (s->tick == NULL) {
        return 0;
    }
    return s->tick(s->ctx);
}

static int pump_once(wcat_stream *src, wcat_stream *dst, const char *label,
                     const wcat_relay_options *opts)
{
    unsigned char buf[WCAT_BUFSIZE];
    ssize_t n;

    do {
        n = src->read(src->ctx, buf, sizeof(buf));
    } while (n < 0 && errno == EINTR);
    if (n < 0 && errno == EIO) {
        return 0;
    }
    if (n < 0 && errno == EAGAIN) {
        return 1;
    }
    if (n <= 0) {
        return 0;
    }
    if (opts != NULL && opts->hex) {
        wcat_hexdump(label, buf, (size_t)n);
    }
    if (dst->write(dst->ctx, buf, (size_t)n) != n) {
        return -1;
    }
    return 1;
}

int wcat_relay_bidirectional(wcat_stream *a, wcat_stream *b,
                             const wcat_relay_options *opts)
{
    struct pollfd pfds[2];
    int af = a->fd(a->ctx);
    int bf = b->fd(b->ctx);
    int timeout = opts != NULL ? opts->timeout_ms : -1;
    int a_active = 1;
    int b_active = 1;

    while (!wcat_stop && (a_active || b_active)) {
        int rc;
        int poll_timeout = timeout;

        if (stream_tick(a) < 0 || stream_tick(b) < 0) {
            return -1;
        }
        if (a_active && a->pending != NULL && a->pending(a->ctx) > 0) {
            rc = pump_once(a, b, "a>b", opts);
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                if (b->shutdown_write != NULL) {
                    (void)b->shutdown_write(b->ctx);
                }
                if (a->close_on_eof) {
                    return 0;
                }
                a_active = 0;
            }
            continue;
        }
        if (b_active && b->pending != NULL && b->pending(b->ctx) > 0) {
            rc = pump_once(b, a, "b>a", opts);
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                if (a->shutdown_write != NULL) {
                    (void)a->shutdown_write(a->ctx);
                }
                if (b->close_on_eof) {
                    return 0;
                }
                b_active = 0;
            }
            continue;
        }
        pfds[0].fd = a_active ? af : -1;
        pfds[0].events = a_active ? POLLIN : 0;
        pfds[0].revents = 0;
        pfds[1].fd = b_active ? bf : -1;
        pfds[1].events = b_active ? POLLIN : 0;
        pfds[1].revents = 0;

        if ((a->tick != NULL || b->tick != NULL) && (poll_timeout < 0 || poll_timeout > 50)) {
            poll_timeout = 50;
        }
        rc = poll(pfds, 2, poll_timeout);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0 && poll_timeout != timeout) {
            continue;
        }
        if (rc == 0) {
            wcat_log(WCAT_LOG_WARN, "timeout", "relay timed out");
            return 0;
        }
        if ((pfds[0].revents & (POLLIN | POLLHUP)) != 0) {
            rc = pump_once(a, b, "a>b", opts);
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                if (b->shutdown_write != NULL) {
                    (void)b->shutdown_write(b->ctx);
                }
                if (a->close_on_eof) {
                    return 0;
                }
                a_active = 0;
            }
        }
        if ((pfds[1].revents & (POLLIN | POLLHUP)) != 0) {
            rc = pump_once(b, a, "b>a", opts);
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                if (a->shutdown_write != NULL) {
                    (void)a->shutdown_write(a->ctx);
                }
                if (b->close_on_eof) {
                    return 0;
                }
                b_active = 0;
            }
        }
    }
    return 0;
}

int wcat_copy_stream(wcat_stream *in, wcat_stream *out,
                     const wcat_relay_options *opts)
{
    int rc;
    while (!wcat_stop) {
        rc = pump_once(in, out, "copy", opts);
        if (rc <= 0) {
            return rc;
        }
    }
    return 0;
}
