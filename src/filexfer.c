#include "access.h"
#include "filexfer.h"
#include "log.h"
#include "proxy.h"
#include "relay.h"
#include "signalx.h"
#include "socketx.h"
#include "tls.h"
#include "util.h"

#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

static int accept_when_ready(int listener, char *host, size_t host_len,
                             char *port, size_t port_len)
{
    struct pollfd pfd;
    int rc;

    while (!wcat_stop) {
        pfd.fd = listener;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, 250);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            continue;
        }
        if ((pfd.revents & POLLIN) != 0) {
            return wcat_accept(listener, host, host_len, port, port_len);
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            errno = ECONNABORTED;
            return -1;
        }
    }
    errno = EINTR;
    return -1;
}

int wcat_send_file(const wcat_config *cfg)
{
    wcat_proxy proxy;
    wcat_tls_stream tls;
    wcat_stream src;
    wcat_stream dst;
    wcat_relay_options opts;
    int file_fd;
    int sock;
    int rc;

    file_fd = open(cfg->file, O_RDONLY);
    if (file_fd < 0) {
        wcat_log_errno("file_open", cfg->file);
        return 1;
    }
    if (wcat_proxy_parse(cfg->proxy_url, &proxy) < 0) {
        wcat_log(WCAT_LOG_ERROR, "proxy_parse", "invalid proxy URL");
        (void)wcat_close_quiet(file_fd);
        return 2;
    }
    sock = cfg->udp ? wcat_udp_connect(cfg->host, cfg->port, cfg->family)
                    : wcat_proxy_connect(&proxy, cfg->host, cfg->port,
                                         cfg->family, cfg->timeout_ms);
    if (sock < 0) {
        wcat_log_errno("connect", "connect failed");
        (void)wcat_close_quiet(file_fd);
        return 1;
    }
    if (cfg->tls) {
        if (wcat_tls_client_open(&tls, sock, cfg->sni != NULL ? cfg->sni : cfg->host,
                                 cfg->tls_verify, cfg->ca_file,
                                 cfg->client_cert_file, cfg->client_key_file) < 0) {
            (void)wcat_close_quiet(file_fd);
            return 1;
        }
        wcat_stream_from_tls(&dst, &tls, "network");
    } else {
        wcat_stream_from_fd(&dst, sock, "network");
    }
    wcat_stream_from_fd(&src, file_fd, "file");
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_copy_stream(&src, &dst, &opts);
    if (cfg->tls) {
        wcat_tls_close(&tls);
    } else {
        (void)wcat_close_quiet(sock);
    }
    (void)wcat_close_quiet(file_fd);
    return rc < 0 ? 1 : 0;
}

int wcat_recv_file(const wcat_config *cfg)
{
    wcat_tls_stream tls;
    wcat_stream src;
    wcat_stream dst;
    wcat_relay_options opts;
    char peer_host[128];
    char peer_port[32];
    int file_fd;
    int listener;
    int client = -1;
    int rc;

    file_fd = open(cfg->file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (file_fd < 0) {
        wcat_log_errno("file_open", cfg->file);
        return 1;
    }
    listener = cfg->udp ? wcat_udp_bind(cfg->host, cfg->port, cfg->family)
                        : wcat_tcp_listen(cfg->host, cfg->port, cfg->family, 16);
    if (listener < 0) {
        wcat_log_errno("listen", "listen failed");
        (void)wcat_close_quiet(file_fd);
        return 1;
    }
    if (cfg->udp) {
        wcat_stream_from_fd(&src, listener, "network");
        wcat_stream_from_fd(&dst, file_fd, "file");
    } else {
        client = accept_when_ready(listener, peer_host, sizeof(peer_host), peer_port, sizeof(peer_port));
        if (client < 0) {
            (void)wcat_close_quiet(listener);
            (void)wcat_close_quiet(file_fd);
            return 1;
        }
        if (!wcat_access_check_fd(cfg, client)) {
            (void)wcat_close_quiet(client);
            (void)wcat_close_quiet(listener);
            (void)wcat_close_quiet(file_fd);
            return 1;
        }
        wcat_log(WCAT_LOG_INFO, "accept", "accepted %s:%s", peer_host, peer_port);
        if (cfg->tls) {
            if (wcat_tls_server_open(&tls, client, cfg->cert_file, cfg->key_file,
                                     cfg->ca_file, cfg->tls_require_client_cert) < 0) {
                (void)wcat_close_quiet(listener);
                (void)wcat_close_quiet(file_fd);
                return 1;
            }
            wcat_stream_from_tls(&src, &tls, "network");
        } else {
            wcat_stream_from_fd(&src, client, "network");
        }
        wcat_stream_from_fd(&dst, file_fd, "file");
    }
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_copy_stream(&src, &dst, &opts);
    if (!cfg->udp) {
        if (cfg->tls) {
            wcat_tls_close(&tls);
        } else {
            (void)wcat_close_quiet(client);
        }
    }
    (void)wcat_close_quiet(listener);
    (void)wcat_close_quiet(file_fd);
    return rc < 0 ? 1 : 0;
}
