#include "quic.h"
#include "log.h"
#include "signalx.h"
#include "socketx.h"
#include "util.h"

#include <errno.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<openssl/quic.h>)
#include <openssl/quic.h>
#define WCAT_HAVE_OPENSSL_QUIC 1
#endif
#endif

#if defined(WCAT_HAVE_OPENSSL_QUIC) && !defined(OPENSSL_NO_QUIC)

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

static int set_alpn(SSL *ssl, const char *alpn)
{
    unsigned char wire[256];
    size_t len;

    if (alpn == NULL) {
        alpn = "wcat/1";
    }
    len = strlen(alpn);
    if (len == 0 || len > 255) {
        errno = EINVAL;
        return -1;
    }
    wire[0] = (unsigned char)len;
    memcpy(wire + 1, alpn, len);
    return SSL_set_alpn_protos(ssl, wire, (unsigned int)(len + 1)) == 0 ? 0 : -1;
}

static int select_alpn_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *out_len, const unsigned char *in,
                          unsigned int in_len, void *arg)
{
    const char *alpn = arg;
    size_t len;
    unsigned int off = 0;

    (void)ssl;
    if (alpn == NULL) {
        alpn = "wcat/1";
    }
    len = strlen(alpn);
    if (len == 0 || len > 255) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    while (off < in_len) {
        unsigned int item_len = in[off];
        off++;
        if (item_len > in_len - off) {
            break;
        }
        if (item_len == len && memcmp(in + off, alpn, len) == 0) {
            *out = in + off;
            *out_len = (unsigned char)item_len;
            return SSL_TLSEXT_ERR_OK;
        }
        off += item_len;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int configure_client_ctx(SSL_CTX *ctx, const wcat_config *cfg)
{
    if (cfg->tls_verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (cfg->ca_file != NULL) {
            if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
                log_openssl_error("quic_ca", "failed to load CA file");
                return -1;
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            log_openssl_error("quic_ca", "failed to load default CA paths");
            return -1;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    if (cfg->client_cert_file != NULL || cfg->client_key_file != NULL) {
        if (cfg->client_cert_file == NULL || cfg->client_key_file == NULL) {
            errno = EINVAL;
            return -1;
        }
        if (SSL_CTX_use_certificate_file(ctx, cfg->client_cert_file, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, cfg->client_key_file, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            log_openssl_error("quic_client_certificate",
                              "failed to load QUIC client certificate or key");
            return -1;
        }
    }
    return 0;
}

static int configure_server_ctx(SSL_CTX *ctx, const wcat_config *cfg)
{
    if (cfg->cert_file == NULL || cfg->key_file == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (SSL_CTX_use_certificate_file(ctx, cfg->cert_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        log_openssl_error("quic_certificate", "failed to load QUIC certificate or key");
        return -1;
    }
    if (cfg->tls_require_client_cert) {
        if (cfg->ca_file == NULL) {
            errno = EINVAL;
            return -1;
        }
        if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            log_openssl_error("quic_ca", "failed to load client certificate CA file");
            return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, (void *)cfg->alpn);
    return 0;
}

static int quic_event_timeout_ms(SSL *ssl, int fallback_ms)
{
    struct timeval tv;
    int is_infinite = 1;
    long ms;

    if (SSL_get_event_timeout(ssl, &tv, &is_infinite) != 1 || is_infinite) {
        return fallback_ms;
    }
    ms = tv.tv_sec * 1000L + (tv.tv_usec + 999L) / 1000L;
    if (ms < 0) {
        return 0;
    }
    if (ms > fallback_ms) {
        return fallback_ms;
    }
    return (int)ms;
}

static int wait_for_quic_activity(SSL *ssl, int fd, int fallback_ms)
{
    struct pollfd pfd;
    int timeout_ms;
    int rc;

    pfd.fd = fd;
    pfd.events = 0;
    pfd.revents = 0;
    if (SSL_net_read_desired(ssl)) {
        pfd.events |= POLLIN;
    }
    if (SSL_net_write_desired(ssl)) {
        pfd.events |= POLLOUT;
    }
    timeout_ms = quic_event_timeout_ms(ssl, fallback_ms);
    if (pfd.events == 0 && timeout_ms < 0) {
        timeout_ms = fallback_ms;
    }
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    return rc;
}

static int open_udp_peer(const wcat_config *cfg, BIO_ADDR **peer_addr)
{
    const BIO_ADDRINFO *ai;
    BIO_ADDRINFO *res = NULL;
    int fd = -1;
    int family = cfg->family == AF_UNSPEC ? AF_UNSPEC : cfg->family;

    if (!BIO_lookup_ex(cfg->host, cfg->port, BIO_LOOKUP_CLIENT, family,
                       SOCK_DGRAM, 0, &res)) {
        log_openssl_error("quic_resolve", "QUIC target resolution failed");
        return -1;
    }
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        fd = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (fd < 0) {
            continue;
        }
        if (!BIO_connect(fd, BIO_ADDRINFO_address(ai), 0) ||
            !BIO_socket_nbio(fd, 1)) {
            BIO_closesocket(fd);
            fd = -1;
            continue;
        }
        *peer_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
        if (*peer_addr == NULL) {
            BIO_closesocket(fd);
            fd = -1;
        }
        break;
    }
    BIO_ADDRINFO_free(res);
    if (fd < 0) {
        wcat_log_errno("quic_connect", "failed to open QUIC UDP peer socket");
    }
    return fd;
}

int wcat_quic_client_open(wcat_tls_stream *s, const wcat_config *cfg)
{
    BIO_ADDR *peer_addr = NULL;
    SSL *conn = NULL;
    int fd;
    const char *servername = cfg->sni != NULL ? cfg->sni : cfg->host;

    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (s->ctx == NULL || configure_client_ctx(s->ctx, cfg) < 0) {
        log_openssl_error("quic_context", "QUIC client context creation failed");
        wcat_tls_close(s);
        return -1;
    }
    fd = open_udp_peer(cfg, &peer_addr);
    if (fd < 0) {
        wcat_tls_close(s);
        return -1;
    }
    s->fd = fd;
    s->owns_fd = true;
    conn = SSL_new(s->ctx);
    if (conn == NULL) {
        BIO_ADDR_free(peer_addr);
        log_openssl_error("quic_session", "QUIC client session creation failed");
        wcat_tls_close(s);
        return -1;
    }
    BIO *bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        SSL_free(conn);
        BIO_ADDR_free(peer_addr);
        log_openssl_error("quic_setup", "failed to attach QUIC socket");
        wcat_tls_close(s);
        return -1;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(conn, bio, bio);
    (void)SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI);
    if (servername != NULL) {
        (void)SSL_set_tlsext_host_name(conn, servername);
        if (cfg->tls_verify && SSL_set1_host(conn, servername) != 1) {
            BIO_ADDR_free(peer_addr);
            SSL_free(conn);
            log_openssl_error("quic_verify", "failed to configure hostname verification");
            wcat_tls_close(s);
            return -1;
        }
    }
    if (set_alpn(conn, cfg->alpn) < 0 ||
        SSL_set1_initial_peer_addr(conn, peer_addr) != 1) {
        BIO_ADDR_free(peer_addr);
        SSL_free(conn);
        log_openssl_error("quic_setup", "failed to configure QUIC session");
        wcat_tls_close(s);
        return -1;
    }
    BIO_ADDR_free(peer_addr);
    if (SSL_connect(conn) != 1) {
        SSL_free(conn);
        log_openssl_error("quic_handshake", "QUIC client handshake failed");
        wcat_tls_close(s);
        return -1;
    }
    if (cfg->tls_verify && SSL_get_verify_result(conn) != X509_V_OK) {
        wcat_log(WCAT_LOG_ERROR, "quic_verify", "QUIC certificate verification failed: %s",
                 X509_verify_cert_error_string(SSL_get_verify_result(conn)));
        SSL_free(conn);
        wcat_tls_close(s);
        return -1;
    }
    if (SSL_set_blocking_mode(conn, 0) != 1) {
        SSL_free(conn);
        log_openssl_error("quic_setup", "failed to configure QUIC nonblocking mode");
        wcat_tls_close(s);
        return -1;
    }
    s->ssl = conn;
    s->enabled = true;
    s->quic_stream = true;
    return 0;
}

int wcat_quic_listener_open(wcat_quic_listener *listener, const wcat_config *cfg)
{
    memset(listener, 0, sizeof(*listener));
    listener->fd = -1;
    listener->ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (listener->ctx == NULL || configure_server_ctx(listener->ctx, cfg) < 0) {
        log_openssl_error("quic_context", "QUIC server context creation failed");
        wcat_quic_listener_close(listener);
        return -1;
    }
    listener->fd = wcat_udp_bind(cfg->host, cfg->port, cfg->family);
    if (listener->fd < 0) {
        wcat_log_errno("quic_bind", "QUIC UDP bind failed");
        wcat_quic_listener_close(listener);
        return -1;
    }
    if (wcat_set_nonblock(listener->fd, 1) < 0) {
        wcat_log_errno("quic_socket", "failed to configure QUIC UDP socket nonblocking");
        wcat_quic_listener_close(listener);
        return -1;
    }
    listener->listener = SSL_new_listener(listener->ctx, 0);
    if (listener->listener == NULL || SSL_set_fd(listener->listener, listener->fd) != 1 ||
        SSL_set_blocking_mode(listener->listener, 0) != 1 ||
        SSL_listen(listener->listener) != 1) {
        log_openssl_error("quic_listen", "failed to start QUIC listener");
        wcat_quic_listener_close(listener);
        return -1;
    }
    return 0;
}

int wcat_quic_accept(wcat_quic_listener *listener, wcat_tls_stream *s)
{
    SSL *conn = NULL;

    memset(s, 0, sizeof(*s));
    s->fd = listener->fd;
    while (!wcat_stop) {
        int rc;

        ERR_clear_error();
        if (SSL_handle_events(listener->listener) != 1) {
            log_openssl_error("quic_accept", "QUIC listener event handling failed");
            return -1;
        }
        conn = SSL_accept_connection(listener->listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (conn != NULL) {
            break;
        }
        rc = wait_for_quic_activity(listener->listener, listener->fd, 250);
        if (rc < 0) {
            wcat_log_errno("quic_accept", "QUIC accept poll failed");
            return -1;
        }
    }
    if (conn == NULL) {
        errno = EINTR;
        return -1;
    }
    if (SSL_set_blocking_mode(conn, 0) != 1) {
        SSL_free(conn);
        log_openssl_error("quic_accept", "failed to configure QUIC nonblocking mode");
        return -1;
    }
    (void)SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI);
    s->ssl = conn;
    s->ctx = NULL;
    s->enabled = true;
    s->owns_fd = false;
    s->quic_stream = true;
    return 0;
}

void wcat_quic_listener_close(wcat_quic_listener *listener)
{
    if (listener == NULL) {
        return;
    }
    if (listener->listener != NULL) {
        SSL_free(listener->listener);
    }
    if (listener->ctx != NULL) {
        SSL_CTX_free(listener->ctx);
    }
    if (listener->fd >= 0) {
        (void)wcat_close_quiet(listener->fd);
    }
    memset(listener, 0, sizeof(*listener));
    listener->fd = -1;
}

#else

int wcat_quic_client_open(wcat_tls_stream *s, const wcat_config *cfg)
{
    (void)s;
    (void)cfg;
    wcat_log(WCAT_LOG_ERROR, "quic_unavailable", "OpenSSL was built without QUIC support");
    return -1;
}

int wcat_quic_listener_open(wcat_quic_listener *listener, const wcat_config *cfg)
{
    (void)listener;
    (void)cfg;
    wcat_log(WCAT_LOG_ERROR, "quic_unavailable", "OpenSSL was built without QUIC support");
    return -1;
}

int wcat_quic_accept(wcat_quic_listener *listener, wcat_tls_stream *s)
{
    (void)listener;
    (void)s;
    return -1;
}

void wcat_quic_listener_close(wcat_quic_listener *listener)
{
    (void)listener;
}

#endif
