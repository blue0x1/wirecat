#include "proxy.h"
#include "access.h"
#include "log.h"
#include "relay.h"
#include "signalx.h"
#include "socketx.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int split_host_port(const char *s, char *host, size_t host_len,
                           char *port, size_t port_len)
{
    const char *colon = strrchr(s, ':');
    size_t len;

    if (colon == NULL || colon == s || colon[1] == '\0') {
        return -1;
    }
    len = (size_t)(colon - s);
    if (len >= host_len || strlen(colon + 1) >= port_len) {
        return -1;
    }
    memcpy(host, s, len);
    host[len] = '\0';
    strcpy(port, colon + 1);
    return wcat_parse_port(port) > 0 ? 0 : -1;
}

int wcat_proxy_parse(const char *url, wcat_proxy *proxy)
{
    const char *rest;

    memset(proxy, 0, sizeof(*proxy));
    if (url == NULL || *url == '\0') {
        proxy->type = WCAT_PROXY_NONE;
        return 0;
    }
    if (strncmp(url, "socks5://", 9) == 0) {
        proxy->type = WCAT_PROXY_SOCKS5;
        rest = url + 9;
    } else if (strncmp(url, "http://", 7) == 0) {
        proxy->type = WCAT_PROXY_HTTP;
        rest = url + 7;
    } else {
        return -1;
    }
    return split_host_port(rest, proxy->host, sizeof(proxy->host),
                           proxy->port, sizeof(proxy->port));
}

static int read_exact(int fd, unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int socks5_negotiate(int fd, const char *dst_host, const char *dst_port)
{
    unsigned char req[512];
    unsigned char rep[10];
    size_t host_len = strlen(dst_host);
    int port = wcat_parse_port(dst_port);

    if (host_len > 255 || port < 0) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 target host or port is invalid");
        errno = EINVAL;
        return -1;
    }
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    if (wcat_full_write(fd, req, 3) != 3 || read_exact(fd, rep, 2) < 0 ||
        rep[0] != 0x05 || rep[1] != 0x00) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 server rejected no-auth negotiation");
        return -1;
    }
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = (unsigned char)host_len;
    memcpy(req + 5, dst_host, host_len);
    req[5 + host_len] = (unsigned char)((port >> 8) & 0xff);
    req[6 + host_len] = (unsigned char)(port & 0xff);
    if (wcat_full_write(fd, req, 7 + host_len) != (ssize_t)(7 + host_len)) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 connect request write failed");
        return -1;
    }
    if (read_exact(fd, rep, 4) < 0 || rep[1] != 0x00) {
        if (rep[1] != 0x00) {
            wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 connect failed with reply code 0x%02x", rep[1]);
        } else {
            wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 connect reply read failed");
        }
        return -1;
    }
    if (rep[3] == 0x01) {
        return read_exact(fd, rep, 6);
    }
    if (rep[3] == 0x03) {
        if (read_exact(fd, rep, 1) < 0) {
            return -1;
        }
        return read_exact(fd, rep, (size_t)rep[0] + 2);
    }
    if (rep[3] == 0x04) {
        return read_exact(fd, rep, 18);
    }
    wcat_log(WCAT_LOG_ERROR, "proxy", "SOCKS5 connect reply used unsupported address type 0x%02x", rep[3]);
    return -1;
}

static int http_connect_negotiate(int fd, const char *dst_host, const char *dst_port)
{
    char req[512];
    char buf[1024];
    size_t used = 0;
    int n;

    n = snprintf(req, sizeof(req),
                 "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: wcat/0.1\r\n\r\n",
                 dst_host, dst_port, dst_host, dst_port);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "HTTP CONNECT request is too large");
        errno = EINVAL;
        return -1;
    }
    if (wcat_full_write(fd, req, (size_t)n) != n) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "HTTP CONNECT request write failed");
        return -1;
    }
    while (used + 1 < sizeof(buf)) {
        ssize_t r = read(fd, buf + used, 1);
        if (r <= 0) {
            wcat_log(WCAT_LOG_ERROR, "proxy", "HTTP CONNECT response read failed");
            return -1;
        }
        used++;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL) {
            break;
        }
    }
    if (strstr(buf, " 200 ") == NULL) {
        wcat_log(WCAT_LOG_ERROR, "proxy", "HTTP CONNECT proxy did not return status 200");
        return -1;
    }
    return 0;
}

int wcat_proxy_connect(const wcat_proxy *proxy, const char *dst_host,
                       const char *dst_port, int family, int timeout_ms)
{
    int fd;

    if (proxy == NULL || proxy->type == WCAT_PROXY_NONE) {
        return wcat_tcp_connect(dst_host, dst_port, family, timeout_ms);
    }
    fd = wcat_tcp_connect(proxy->host, proxy->port, family, timeout_ms);
    if (fd < 0) {
        return -1;
    }
    if (proxy->type == WCAT_PROXY_SOCKS5) {
        if (socks5_negotiate(fd, dst_host, dst_port) == 0) {
            return fd;
        }
    } else if (proxy->type == WCAT_PROXY_HTTP) {
        if (http_connect_negotiate(fd, dst_host, dst_port) == 0) {
            return fd;
        }
    }
    wcat_log(WCAT_LOG_ERROR, "proxy", "proxy negotiation failed");
    return wcat_close_quiet(fd);
}

static int read_http_header(int fd, char *buf, size_t len)
{
    size_t used = 0;

    while (used + 1 < len) {
        ssize_t n = read(fd, buf + used, 1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL) {
            return 0;
        }
    }
    errno = EMSGSIZE;
    return -1;
}

static int parse_connect_request(const char *buf, char *host, size_t host_len,
                                 char *port, size_t port_len)
{
    const char *target;
    const char *space;
    char endpoint[512];
    size_t len;

    if (strncmp(buf, "CONNECT ", 8) != 0) {
        return -1;
    }
    target = buf + 8;
    space = strchr(target, ' ');
    if (space == NULL) {
        return -1;
    }
    len = (size_t)(space - target);
    if (len == 0 || len >= sizeof(endpoint)) {
        return -1;
    }
    memcpy(endpoint, target, len);
    endpoint[len] = '\0';
    return split_host_port(endpoint, host, host_len, port, port_len);
}

static int write_proxy_response(int fd, int status, const char *text)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n\r\n", status, text);

    if (n < 0 || (size_t)n >= sizeof(buf)) {
        errno = EINVAL;
        return -1;
    }
    return wcat_full_write(fd, buf, (size_t)n) == n ? 0 : -1;
}

static int serve_proxy_client(const wcat_config *cfg, int client)
{
    char req[4096];
    char host[256];
    char port[32];
    int upstream = -1;
    wcat_stream client_stream;
    wcat_stream upstream_stream;
    wcat_relay_options opts;
    int rc;

    if (read_http_header(client, req, sizeof(req)) < 0 ||
        parse_connect_request(req, host, sizeof(host), port, sizeof(port)) < 0) {
        (void)write_proxy_response(client, 400, "Bad Request");
        return 1;
    }
    upstream = wcat_tcp_connect(host, port, cfg->family, cfg->timeout_ms);
    if (upstream < 0) {
        (void)write_proxy_response(client, 502, "Bad Gateway");
        wcat_log_errno("proxy_connect", "proxy upstream connect failed");
        return 1;
    }
    if (write_proxy_response(client, 200, "Connection Established") < 0) {
        (void)wcat_close_quiet(upstream);
        return 1;
    }
    wcat_log(WCAT_LOG_INFO, "proxy_connect", "proxy CONNECT %s:%s", host, port);
    wcat_stream_from_fd(&client_stream, client, "proxy-client");
    wcat_stream_from_fd(&upstream_stream, upstream, "proxy-upstream");
    client_stream.close_on_eof = 0;
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(&client_stream, &upstream_stream, &opts);
    (void)wcat_close_quiet(upstream);
    return rc < 0 ? 1 : 0;
}

int wcat_proxy_server_run(const wcat_config *cfg)
{
    int listener;
    int rc = 0;

    listener = wcat_tcp_listen(cfg->host, cfg->port, cfg->family, 64);
    if (listener < 0) {
        wcat_log_errno("proxy_listen", "HTTP CONNECT proxy listen failed");
        return 1;
    }
    wcat_log(WCAT_LOG_INFO, "proxy_listen", "HTTP CONNECT proxy listening on %s:%s",
             cfg->host, cfg->port);
    while (!wcat_stop) {
        char host[128] = "";
        char port[32] = "";
        int client = wcat_accept(listener, host, sizeof(host), port, sizeof(port));

        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            wcat_log_errno("proxy_accept", "proxy accept failed");
            rc = 1;
            break;
        }
        if (!wcat_access_check_fd(cfg, client)) {
            (void)wcat_close_quiet(client);
            continue;
        }
        wcat_log(WCAT_LOG_INFO, "proxy_accept", "accepted proxy client %s:%s", host, port);
        rc = serve_proxy_client(cfg, client);
        (void)wcat_close_quiet(client);
        if (rc != 0 && !cfg->keep_open) {
            break;
        }
        rc = 0;
    }
    (void)wcat_close_quiet(listener);
    return rc;
}
