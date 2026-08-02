#include "access.h"
#include "broker.h"
#include "cli.h"
#include "filexfer.h"
#include "log.h"
#include "process.h"
#include "proxy.h"
#include "quic.h"
#include "relay.h"
#include "signalx.h"
#include "socketx.h"
#include "tls.h"
#include "util.h"
#include "version.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    wcat_stream stream;
    wcat_process proc;
    int fd1;
    int fd2;
    int has_proc;
} relay_endpoint;

static void relay_endpoint_init(relay_endpoint *ep)
{
    memset(ep, 0, sizeof(*ep));
    ep->fd1 = -1;
    ep->fd2 = -1;
    ep->proc.pid = -1;
    ep->proc.in_fd = -1;
    ep->proc.out_fd = -1;
    ep->proc.err_fd = -1;
    ep->proc.pty_fd = -1;
}

static void relay_endpoint_close(relay_endpoint *ep)
{
    if (ep->has_proc) {
        wcat_process_close(&ep->proc);
        (void)wcat_process_wait(&ep->proc);
    } else {
        if (ep->fd1 >= 0) {
            (void)wcat_close_quiet(ep->fd1);
        }
        if (ep->fd2 >= 0 && ep->fd2 != ep->fd1) {
            (void)wcat_close_quiet(ep->fd2);
        }
    }
}

static int split_spec_host_port(const char *spec, const char *prefix,
                                char *host, size_t host_len,
                                char *port, size_t port_len)
{
    const char *rest = spec + strlen(prefix);
    const char *colon = strrchr(rest, ':');
    size_t len;

    if (colon == NULL || colon == rest || colon[1] == '\0') {
        return -1;
    }
    len = (size_t)(colon - rest);
    if (len >= host_len || strlen(colon + 1) >= port_len) {
        return -1;
    }
    memcpy(host, rest, len);
    host[len] = '\0';
    strcpy(port, colon + 1);
    return wcat_parse_port(port) > 0 ? 0 : -1;
}

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

static int open_relay_endpoint(const wcat_config *cfg, const char *spec, relay_endpoint *ep)
{
    char host[256];
    char port[32];

    if (strcmp(spec, "-") == 0 || strcmp(spec, "stdio") == 0) {
        wcat_stream_from_fd_pair(&ep->stream, STDIN_FILENO, STDOUT_FILENO, "stdio");
        return 0;
    }
    if (strncmp(spec, "tcp:", 4) == 0) {
        if (split_spec_host_port(spec, "tcp:", host, sizeof(host), port, sizeof(port)) < 0) {
            wcat_log(WCAT_LOG_ERROR, "relay_spec", "invalid tcp relay spec");
            return 2;
        }
        ep->fd1 = wcat_tcp_connect(host, port, cfg->family, cfg->timeout_ms);
        if (ep->fd1 < 0) {
            wcat_log_errno("relay_connect", "tcp relay connect failed");
            return 1;
        }
        wcat_stream_from_fd(&ep->stream, ep->fd1, "tcp");
        return 0;
    }
    if (strncmp(spec, "unix:", 5) == 0) {
        ep->fd1 = wcat_unix_connect(spec + 5, cfg->timeout_ms);
        if (ep->fd1 < 0) {
            wcat_log_errno("relay_connect", "unix relay connect failed");
            return 1;
        }
        wcat_stream_from_fd(&ep->stream, ep->fd1, "unix");
        return 0;
    }
    if (strncmp(spec, "listen:", 7) == 0) {
        if (split_spec_host_port(spec, "listen:", host, sizeof(host), port, sizeof(port)) < 0) {
            wcat_log(WCAT_LOG_ERROR, "relay_spec", "invalid listen relay spec");
            return 2;
        }
        ep->fd1 = wcat_tcp_listen(host, port, cfg->family, 16);
        if (ep->fd1 < 0) {
            wcat_log_errno("relay_listen", "tcp relay listen failed");
            return 1;
        }
        ep->fd2 = accept_when_ready(ep->fd1, NULL, 0, NULL, 0);
        if (ep->fd2 < 0) {
            wcat_log_errno("relay_accept", "tcp relay accept failed");
            return 1;
        }
        (void)wcat_close_quiet(ep->fd1);
        ep->fd1 = ep->fd2;
        ep->fd2 = -1;
        wcat_stream_from_fd(&ep->stream, ep->fd1, "listen");
        return 0;
    }
    if (strncmp(spec, "unix-listen:", 12) == 0) {
        ep->fd1 = wcat_unix_listen(spec + 12, 16);
        if (ep->fd1 < 0) {
            wcat_log_errno("relay_listen", "unix relay listen failed");
            return 1;
        }
        ep->fd2 = accept_when_ready(ep->fd1, NULL, 0, NULL, 0);
        if (ep->fd2 < 0) {
            wcat_log_errno("relay_accept", "unix relay accept failed");
            return 1;
        }
        (void)wcat_close_quiet(ep->fd1);
        ep->fd1 = ep->fd2;
        ep->fd2 = -1;
        wcat_stream_from_fd(&ep->stream, ep->fd1, "unix-listen");
        return 0;
    }
    if (strncmp(spec, "file:", 5) == 0) {
        ep->fd1 = open(spec + 5, O_RDWR | O_CREAT, 0600);
        if (ep->fd1 < 0) {
            wcat_log_errno("relay_file", spec + 5);
            return 1;
        }
        wcat_stream_from_fd(&ep->stream, ep->fd1, "file");
        return 0;
    }
    if (strncmp(spec, "exec:", 5) == 0 || strncmp(spec, "pty:", 4) == 0) {
        const char *path = spec[0] == 'p' ? spec + 4 : spec + 5;
        int use_pty = spec[0] == 'p';
        if (wcat_process_spawn(path, use_pty, &ep->proc) < 0) {
            wcat_log_errno("relay_exec", path);
            return 1;
        }
        ep->has_proc = 1;
        wcat_stream_from_fd_pair(&ep->stream, ep->proc.out_fd, ep->proc.in_fd, "process");
        return 0;
    }
    wcat_log(WCAT_LOG_ERROR, "relay_spec",
             "unknown relay spec '%s' (use -, tcp:host:port, listen:host:port, unix:path, unix-listen:path, file:path, exec:path, pty:path)",
             spec);
    return 2;
}

static int connect_socket(const wcat_config *cfg)
{
    wcat_proxy proxy;

    if (cfg->udp) {
        return wcat_udp_connect(cfg->host, cfg->port, cfg->family);
    }
    if (cfg->unix_socket) {
        return wcat_unix_connect(cfg->host, cfg->timeout_ms);
    }
    if (cfg->vsock) {
        return wcat_vsock_connect(cfg->host, cfg->port, cfg->timeout_ms);
    }
    if (cfg->sctp) {
        return wcat_sctp_connect(cfg->host, cfg->port, cfg->family, cfg->timeout_ms);
    }
    if (wcat_proxy_parse(cfg->proxy_url, &proxy) < 0) {
        wcat_log(WCAT_LOG_ERROR, "proxy_parse", "invalid proxy URL");
        errno = EINVAL;
        return -1;
    }
    return wcat_proxy_connect(&proxy, cfg->host, cfg->port, cfg->family, cfg->timeout_ms);
}

static int relay_stream_to_stdio(const wcat_config *cfg, wcat_stream *net)
{
    wcat_stream stdio_stream;
    wcat_relay_options opts;
    int rc;

    wcat_stream_from_fd_pair(&stdio_stream, STDIN_FILENO, STDOUT_FILENO, "stdio");
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(net, &stdio_stream, &opts);
    return rc < 0 ? 1 : 0;
}

static int relay_stream_to_process(const wcat_config *cfg, wcat_stream *net)
{
    wcat_stream proc_stream;
    wcat_process proc;
    wcat_relay_options opts;
    int rc;

    if (wcat_process_spawn(cfg->exec_path, cfg->pty, &proc) < 0) {
        wcat_log_errno("process_spawn", cfg->exec_path);
        return 1;
    }
    net->close_on_eof = 0;
    wcat_stream_from_fd_pair(&proc_stream, proc.out_fd, proc.in_fd, "process");
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(net, &proc_stream, &opts);
    wcat_process_close(&proc);
    (void)wcat_process_wait(&proc);
    return rc < 0 ? 1 : 0;
}

static int serve_quic_stream(const wcat_config *cfg, wcat_tls_stream *quic)
{
    wcat_stream net;
    int rc;

    wcat_stream_from_tls(&net, quic, "quic");
    if (cfg->exec_path != NULL) {
        rc = relay_stream_to_process(cfg, &net);
    } else {
        rc = relay_stream_to_stdio(cfg, &net);
    }
    wcat_tls_close(quic);
    return rc;
}

static int run_quic_connect(const wcat_config *cfg)
{
    wcat_tls_stream quic;

    if (wcat_quic_client_open(&quic, cfg) < 0) {
        return 1;
    }
    wcat_log(WCAT_LOG_INFO, "connect", "connected to %s:%s over QUIC", cfg->host, cfg->port);
    return serve_quic_stream(cfg, &quic);
}

static int run_quic_listen(const wcat_config *cfg)
{
    wcat_quic_listener listener;
    wcat_tls_stream quic;
    int rc;

    if (wcat_quic_listener_open(&listener, cfg) < 0) {
        return 1;
    }
    wcat_log(WCAT_LOG_INFO, "listen", "QUIC listening on %s:%s", cfg->host, cfg->port);
    if (wcat_quic_accept(&listener, &quic) < 0) {
        wcat_quic_listener_close(&listener);
        return wcat_stop ? 0 : 1;
    }
    wcat_log(WCAT_LOG_INFO, "accept", "accepted QUIC peer");
    rc = serve_quic_stream(cfg, &quic);
    wcat_quic_listener_close(&listener);
    return rc;
}

static int relay_peer_to_stdio(const wcat_config *cfg, int fd, int server_side)
{
    wcat_tls_stream tls;
    wcat_stream net;
    wcat_stream stdio_stream;
    wcat_relay_options opts;
    int rc;

    if (cfg->tls) {
        if (server_side) {
            if (wcat_tls_server_open(&tls, fd, cfg->cert_file, cfg->key_file,
                                     cfg->ca_file, cfg->tls_require_client_cert) < 0) {
                return 1;
            }
        } else if (wcat_tls_client_open(&tls, fd, cfg->sni != NULL ? cfg->sni : cfg->host,
                                        cfg->tls_verify, cfg->ca_file,
                                        cfg->client_cert_file, cfg->client_key_file) < 0) {
            return 1;
        }
        wcat_stream_from_tls(&net, &tls, "network");
    } else {
        wcat_stream_from_fd(&net, fd, "network");
        if (cfg->sctp) {
            net.can_close_write = 0;
        }
    }

    wcat_stream_from_fd_pair(&stdio_stream, STDIN_FILENO, STDOUT_FILENO, "stdio");
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(&net, &stdio_stream, &opts);
    if (cfg->tls) {
        wcat_tls_close(&tls);
    } else {
        (void)wcat_close_quiet(fd);
    }
    return rc < 0 ? 1 : 0;
}

static int relay_peer_to_process(const wcat_config *cfg, int fd, int server_side)
{
    wcat_tls_stream tls;
    wcat_stream net;
    wcat_stream proc_stream;
    wcat_process proc;
    wcat_relay_options opts;
    int rc;

    if (wcat_process_spawn(cfg->exec_path, cfg->pty, &proc) < 0) {
        wcat_log_errno("process_spawn", cfg->exec_path);
        return 1;
    }
    if (cfg->tls) {
        if (server_side) {
            if (wcat_tls_server_open(&tls, fd, cfg->cert_file, cfg->key_file,
                                     cfg->ca_file, cfg->tls_require_client_cert) < 0) {
                wcat_process_close(&proc);
                (void)wcat_process_wait(&proc);
                return 1;
            }
        } else if (wcat_tls_client_open(&tls, fd, cfg->sni != NULL ? cfg->sni : cfg->host,
                                        cfg->tls_verify, cfg->ca_file,
                                        cfg->client_cert_file, cfg->client_key_file) < 0) {
            wcat_process_close(&proc);
            (void)wcat_process_wait(&proc);
            return 1;
        }
        wcat_stream_from_tls(&net, &tls, "network");
    } else {
        wcat_stream_from_fd(&net, fd, "network");
        if (cfg->sctp) {
            net.can_close_write = 0;
        }
    }
    net.close_on_eof = 0;
    wcat_stream_from_fd_pair(&proc_stream, proc.out_fd, proc.in_fd, "process");
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(&net, &proc_stream, &opts);
    wcat_process_close(&proc);
    (void)wcat_process_wait(&proc);
    if (cfg->tls) {
        wcat_tls_close(&tls);
    } else {
        (void)wcat_close_quiet(fd);
    }
    return rc < 0 ? 1 : 0;
}

static int run_connect(const wcat_config *cfg)
{
    int fd = connect_socket(cfg);

    if (fd < 0) {
        wcat_log_errno("connect", "connect failed");
        return 1;
    }
    wcat_log(WCAT_LOG_INFO, "connect", "connected to %s:%s", cfg->host, cfg->port);
    if (cfg->exec_path != NULL) {
        return relay_peer_to_process(cfg, fd, 0);
    }
    return relay_peer_to_stdio(cfg, fd, 0);
}

static int serve_client(const wcat_config *cfg, int client)
{
    if (cfg->exec_path != NULL) {
        return relay_peer_to_process(cfg, client, 1);
    }
    return relay_peer_to_stdio(cfg, client, 1);
}

static int run_listen(const wcat_config *cfg)
{
    int listener;
    int rc = 0;

    if (cfg->udp) {
        listener = wcat_udp_bind(cfg->host, cfg->port, cfg->family);
        if (listener < 0) {
            wcat_log_errno("listen", "UDP bind failed");
            return 1;
        }
        return serve_client(cfg, listener);
    }

    if (cfg->unix_socket) {
        listener = wcat_unix_listen(cfg->host, 16);
    } else if (cfg->vsock) {
        listener = wcat_vsock_listen(cfg->host, cfg->port, 16);
    } else if (cfg->sctp) {
        listener = wcat_sctp_listen(cfg->host, cfg->port, cfg->family, 16);
    } else {
        listener = wcat_tcp_listen(cfg->host, cfg->port, cfg->family, 16);
    }
    if (listener < 0) {
        wcat_log_errno("listen", "listen failed");
        return 1;
    }
    if (cfg->unix_socket) {
        wcat_log(WCAT_LOG_INFO, "listen", "listening on unix:%s", cfg->host);
    } else {
        wcat_log(WCAT_LOG_INFO, "listen", "listening on %s:%s", cfg->host, cfg->port);
    }
    do {
        char host[128] = "";
        char port[32] = "";
        int client = accept_when_ready(listener, host, sizeof(host), port, sizeof(port));
        if (client < 0) {
            if (wcat_stop) {
                break;
            }
            wcat_log_errno("accept", "accept failed");
            rc = 1;
            break;
        }
        if (!wcat_access_check_fd(cfg, client)) {
            (void)wcat_close_quiet(client);
            continue;
        }
        wcat_log(WCAT_LOG_INFO, "accept", "accepted %s:%s", host, port);
        rc = serve_client(cfg, client);
    } while (cfg->keep_open && !wcat_stop);

    (void)wcat_close_quiet(listener);
    return rc;
}

static int run_relay(const wcat_config *cfg)
{
    relay_endpoint left;
    relay_endpoint right;
    wcat_relay_options opts;
    int rc;

    relay_endpoint_init(&left);
    relay_endpoint_init(&right);

    rc = open_relay_endpoint(cfg, cfg->left, &left);
    if (rc == 0) {
        rc = open_relay_endpoint(cfg, cfg->right, &right);
    }
    if (rc != 0) {
        relay_endpoint_close(&left);
        relay_endpoint_close(&right);
        return rc;
    }
    if (left.has_proc && !right.has_proc) {
        right.stream.close_on_eof = 0;
    }
    if (right.has_proc && !left.has_proc) {
        left.stream.close_on_eof = 0;
    }
    opts.timeout_ms = cfg->timeout_ms;
    opts.hex = cfg->hex;
    rc = wcat_relay_bidirectional(&left.stream, &right.stream, &opts);
    relay_endpoint_close(&left);
    relay_endpoint_close(&right);
    return rc < 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    wcat_config cfg;
    int parsed;
    int rc;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("wcat %s\n", WCAT_VERSION);
        printf("Author: %s\n", WCAT_AUTHOR);
        return 0;
    }

    parsed = wcat_parse_args(argc, argv, &cfg);
    if (parsed != 0) {
        wcat_print_help(argv[0]);
        return parsed > 0 ? 0 : 2;
    }
    wcat_log_init(cfg.json, cfg.verbose);
    if (wcat_signal_setup() < 0) {
        wcat_log_errno("signal", "signal setup failed");
        return 1;
    }
    if (wcat_tls_global_init() < 0) {
        wcat_log(WCAT_LOG_ERROR, "tls_init", "OpenSSL initialization failed");
        return 1;
    }

    switch (cfg.mode) {
    case WCAT_MODE_CONNECT:
        rc = cfg.quic ? run_quic_connect(&cfg) : run_connect(&cfg);
        break;
    case WCAT_MODE_LISTEN:
        rc = cfg.quic ? run_quic_listen(&cfg) : run_listen(&cfg);
        break;
    case WCAT_MODE_SEND:
        rc = wcat_send_file(&cfg);
        break;
    case WCAT_MODE_RECV:
        rc = wcat_recv_file(&cfg);
        break;
    case WCAT_MODE_RELAY:
        rc = run_relay(&cfg);
        break;
    case WCAT_MODE_BROKER:
        rc = wcat_broker_run(&cfg);
        break;
    case WCAT_MODE_PROXY:
        rc = wcat_proxy_server_run(&cfg);
        break;
    case WCAT_MODE_NONE:
    default:
        rc = 2;
        break;
    }
    wcat_tls_global_cleanup();
    return rc;
}
