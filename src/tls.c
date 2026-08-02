#include "tls.h"
#include "log.h"
#include "signalx.h"
#include "socketx.h"
#include "util.h"

#include <errno.h>
#include <poll.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>

int wcat_tls_global_init(void)
{
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return -1;
    }
    return 0;
}

void wcat_tls_global_cleanup(void)
{
}

static void stream_init(wcat_tls_stream *s, int fd)
{
    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->enabled = true;
    s->owns_fd = true;
}

static void log_openssl_error(const char *event, const char *message)
{
    unsigned long err;
    char buf[256];

    err = ERR_get_error();
    if (err == 0) {
        wcat_log(WCAT_LOG_ERROR, event, "%s", message);
        return;
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    wcat_log(WCAT_LOG_ERROR, event, "%s: %s", message, buf);
}

static SSL *quic_event_ssl(wcat_tls_stream *s)
{
    if (s == NULL || !s->quic_stream) {
        return NULL;
    }
    return s->parent_ssl != NULL ? s->parent_ssl : s->ssl;
}

static void quic_handle_events(wcat_tls_stream *s)
{
    SSL *ssl = quic_event_ssl(s);

    if (ssl != NULL) {
#ifdef WCAT_HAVE_OPENSSL_QUIC_API
        (void)SSL_handle_events(ssl);
#endif
    }
}

int wcat_tls_client_open(wcat_tls_stream *s, int fd, const char *servername,
                         int verify_peer, const char *ca_file,
                         const char *client_cert, const char *client_key)
{
    stream_init(s, fd);
    s->ctx = SSL_CTX_new(TLS_client_method());
    if (s->ctx == NULL) {
        log_openssl_error("tls_context", "TLS client context creation failed");
        wcat_tls_close(s);
        return -1;
    }
    SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION);
    if (verify_peer) {
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
        if (ca_file != NULL) {
            if (SSL_CTX_load_verify_locations(s->ctx, ca_file, NULL) != 1) {
                log_openssl_error("tls_ca", "failed to load CA file");
                wcat_tls_close(s);
                return -1;
            }
        } else if (SSL_CTX_set_default_verify_paths(s->ctx) != 1) {
            log_openssl_error("tls_ca", "failed to load default CA paths");
            wcat_tls_close(s);
            return -1;
        }
    } else {
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_NONE, NULL);
    }
    if (client_cert != NULL || client_key != NULL) {
        if (client_cert == NULL || client_key == NULL) {
            errno = EINVAL;
            wcat_tls_close(s);
            return -1;
        }
        if (SSL_CTX_use_certificate_file(s->ctx, client_cert, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(s->ctx, client_key, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(s->ctx) != 1) {
            log_openssl_error("tls_client_certificate",
                              "failed to load TLS client certificate or key");
            wcat_tls_close(s);
            return -1;
        }
    }
    s->ssl = SSL_new(s->ctx);
    if (s->ssl == NULL) {
        log_openssl_error("tls_session", "TLS client session creation failed");
        wcat_tls_close(s);
        return -1;
    }
    SSL_set_fd(s->ssl, fd);
    if (servername != NULL) {
        (void)SSL_set_tlsext_host_name(s->ssl, servername);
        if (verify_peer && SSL_set1_host(s->ssl, servername) != 1) {
            log_openssl_error("tls_verify", "failed to configure hostname verification");
            wcat_tls_close(s);
            return -1;
        }
    }
    if (SSL_connect(s->ssl) != 1) {
        log_openssl_error("tls_handshake", "TLS client handshake failed");
        wcat_tls_close(s);
        return -1;
    }
    if (verify_peer && SSL_get_verify_result(s->ssl) != X509_V_OK) {
        wcat_log(WCAT_LOG_ERROR, "tls_verify", "TLS certificate verification failed: %s",
                 X509_verify_cert_error_string(SSL_get_verify_result(s->ssl)));
        wcat_tls_close(s);
        return -1;
    }
    (void)wcat_set_nonblock(fd, 1);
    return 0;
}

int wcat_tls_server_open(wcat_tls_stream *s, int fd, const char *cert, const char *key,
                         const char *ca_file, int require_client_cert)
{
    stream_init(s, fd);
    if (cert == NULL || key == NULL) {
        errno = EINVAL;
        wcat_tls_close(s);
        return -1;
    }
    s->ctx = SSL_CTX_new(TLS_server_method());
    if (s->ctx == NULL) {
        log_openssl_error("tls_context", "TLS server context creation failed");
        wcat_tls_close(s);
        return -1;
    }
    SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(s->ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(s->ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(s->ctx) != 1) {
        log_openssl_error("tls_certificate", "failed to load TLS certificate or key");
        wcat_tls_close(s);
        return -1;
    }
    if (require_client_cert) {
        if (ca_file == NULL) {
            errno = EINVAL;
            wcat_tls_close(s);
            return -1;
        }
        if (SSL_CTX_load_verify_locations(s->ctx, ca_file, NULL) != 1) {
            log_openssl_error("tls_ca", "failed to load client certificate CA file");
            wcat_tls_close(s);
            return -1;
        }
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    s->ssl = SSL_new(s->ctx);
    if (s->ssl == NULL) {
        log_openssl_error("tls_session", "TLS server session creation failed");
        wcat_tls_close(s);
        return -1;
    }
    SSL_set_fd(s->ssl, fd);
    if (SSL_accept(s->ssl) != 1) {
        log_openssl_error("tls_handshake", "TLS server handshake failed");
        wcat_tls_close(s);
        return -1;
    }
    if (require_client_cert && SSL_get_verify_result(s->ssl) != X509_V_OK) {
        wcat_log(WCAT_LOG_ERROR, "tls_verify", "TLS client certificate verification failed: %s",
                 X509_verify_cert_error_string(SSL_get_verify_result(s->ssl)));
        wcat_tls_close(s);
        return -1;
    }
    (void)wcat_set_nonblock(fd, 1);
    return 0;
}

ssize_t wcat_tls_read(wcat_tls_stream *s, void *buf, size_t len)
{
    int rc;

    quic_handle_events(s);
    rc = SSL_read(s->ssl, buf, (int)len);
    if (rc <= 0) {
        int err = SSL_get_error(s->ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            quic_handle_events(s);
            errno = EAGAIN;
            return -1;
        }
        return 0;
    }
    return rc;
}

ssize_t wcat_tls_write(wcat_tls_stream *s, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t off = 0;

    while (off < len) {
        int rc;

        quic_handle_events(s);
        rc = SSL_write(s->ssl, p + off, (int)(len - off));
        if (rc > 0) {
            off += (size_t)rc;
            quic_handle_events(s);
            continue;
        }
        rc = SSL_get_error(s->ssl, rc);
        if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd;
            int prc;

            quic_handle_events(s);
            pfd.fd = s->fd;
            pfd.events = rc == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            pfd.revents = 0;
            do {
                prc = poll(&pfd, 1, -1);
            } while (prc < 0 && errno == EINTR);
            if (prc <= 0) {
                return -1;
            }
            continue;
        }
        return -1;
    }
    quic_handle_events(s);
    return (ssize_t)off;
}

int wcat_tls_pending(wcat_tls_stream *s)
{
    quic_handle_events(s);
    return SSL_pending(s->ssl);
}

int wcat_tls_tick(wcat_tls_stream *s)
{
    SSL *ssl = quic_event_ssl(s);

    if (ssl != NULL) {
#ifdef WCAT_HAVE_OPENSSL_QUIC_API
        return SSL_handle_events(ssl) == 1 ? 0 : -1;
#else
        return 0;
#endif
    }
    return 0;
}

int wcat_tls_shutdown_write(wcat_tls_stream *s)
{
    int rc;

    if (s == NULL || s->ssl == NULL) {
        return 0;
    }
    if (s->quic_stream) {
#ifndef WCAT_HAVE_OPENSSL_QUIC_API
        errno = ENOTSUP;
        return -1;
#else
        while (!wcat_stop) {
            struct pollfd pfd;
            int prc;

            quic_handle_events(s);
            rc = SSL_stream_conclude(s->ssl, 0);
            if (rc == 1) {
                return 0;
            }
            rc = SSL_get_error(s->ssl, rc);
            if (rc != SSL_ERROR_WANT_READ && rc != SSL_ERROR_WANT_WRITE) {
                return -1;
            }
            pfd.fd = s->fd;
            pfd.events = rc == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            pfd.revents = 0;
            do {
                prc = poll(&pfd, 1, 100);
            } while (prc < 0 && errno == EINTR);
            if (prc < 0) {
                return -1;
            }
        }
        return 0;
#endif
    }
    rc = SSL_shutdown(s->ssl);
    if (rc >= 0) {
        return 0;
    }
    rc = SSL_get_error(s->ssl, rc);
    if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
        return 0;
    }
    return -1;
}

void wcat_tls_close(wcat_tls_stream *s)
{
    if (s == NULL) {
        return;
    }
    if (s->ssl != NULL) {
        (void)SSL_shutdown(s->ssl);
        SSL_free(s->ssl);
    }
    if (s->parent_ssl != NULL && s->parent_ssl != s->ssl) {
        SSL_free(s->parent_ssl);
    }
    if (s->ctx != NULL) {
        SSL_CTX_free(s->ctx);
    }
    if (s->owns_fd && s->fd >= 0) {
        (void)wcat_close_quiet(s->fd);
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}
