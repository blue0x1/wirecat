#ifndef WCAT_RELAY_H
#define WCAT_RELAY_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "tls.h"

typedef ssize_t (*wcat_stream_read_fn)(void *ctx, void *buf, size_t len);
typedef ssize_t (*wcat_stream_write_fn)(void *ctx, const void *buf, size_t len);
typedef int (*wcat_stream_fd_fn)(void *ctx);
typedef int (*wcat_stream_shutdown_write_fn)(void *ctx);
typedef int (*wcat_stream_pending_fn)(void *ctx);
typedef int (*wcat_stream_tick_fn)(void *ctx);

typedef struct {
    void *ctx;
    wcat_stream_read_fn read;
    wcat_stream_write_fn write;
    wcat_stream_fd_fn fd;
    wcat_stream_shutdown_write_fn shutdown_write;
    wcat_stream_pending_fn pending;
    wcat_stream_tick_fn tick;
    const char *name;
    int raw_fd;
    int write_fd;
    int can_close_write;
    int close_on_eof;
} wcat_stream;

typedef struct {
    int timeout_ms;
    bool hex;
} wcat_relay_options;

void wcat_stream_from_fd(wcat_stream *s, int fd, const char *name);
void wcat_stream_from_fd_pair(wcat_stream *s, int read_fd, int write_fd, const char *name);
void wcat_stream_from_tls(wcat_stream *s, wcat_tls_stream *tls, const char *name);
int wcat_relay_bidirectional(wcat_stream *a, wcat_stream *b,
                             const wcat_relay_options *opts);
int wcat_copy_stream(wcat_stream *in, wcat_stream *out,
                     const wcat_relay_options *opts);

#endif
