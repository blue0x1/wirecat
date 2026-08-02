#ifndef WCAT_TLS_H
#define WCAT_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <openssl/ssl.h>

#if defined(OPENSSL_VERSION_MAJOR) && \
    (OPENSSL_VERSION_MAJOR > 3 || (OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR >= 2))
#define WCAT_HAVE_OPENSSL_QUIC_API 1
#endif

typedef struct {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
    SSL *parent_ssl;
    bool enabled;
    bool owns_fd;
    bool quic_stream;
} wcat_tls_stream;

int wcat_tls_global_init(void);
void wcat_tls_global_cleanup(void);
int wcat_tls_client_open(wcat_tls_stream *s, int fd, const char *servername,
                         int verify_peer, const char *ca_file,
                         const char *client_cert, const char *client_key);
int wcat_tls_server_open(wcat_tls_stream *s, int fd, const char *cert, const char *key,
                         const char *ca_file, int require_client_cert);
ssize_t wcat_tls_read(wcat_tls_stream *s, void *buf, size_t len);
ssize_t wcat_tls_write(wcat_tls_stream *s, const void *buf, size_t len);
int wcat_tls_pending(wcat_tls_stream *s);
int wcat_tls_tick(wcat_tls_stream *s);
int wcat_tls_shutdown_write(wcat_tls_stream *s);
void wcat_tls_close(wcat_tls_stream *s);

#endif
