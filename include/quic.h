#ifndef WCAT_QUIC_H
#define WCAT_QUIC_H

#include "cli.h"
#include "tls.h"

typedef struct {
    SSL_CTX *ctx;
    SSL *listener;
    int fd;
} wcat_quic_listener;

int wcat_quic_client_open(wcat_tls_stream *s, const wcat_config *cfg);
int wcat_quic_listener_open(wcat_quic_listener *listener, const wcat_config *cfg);
int wcat_quic_accept(wcat_quic_listener *listener, wcat_tls_stream *s);
void wcat_quic_listener_close(wcat_quic_listener *listener);

#endif
