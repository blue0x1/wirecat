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
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define WCAT_MULTI_LIMIT 256
#define WCAT_MULTI_BUFSIZE 4096
#define WCAT_MULTI_INPUT 8192
#define WCAT_MULTI_HISTORY 64
#define WCAT_MULTI_ECHO_PENDING 8192

typedef struct {
    wcat_stream stream;
    wcat_process proc;
    int fd1;
    int fd2;
    int has_proc;
} relay_endpoint;

typedef struct {
    int fd;
    unsigned int id;
    char name[32];
    char host[128];
    char port[32];
    size_t rx_bytes;
    size_t tx_bytes;
    int line_start;
} multi_session;

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

static void multi_session_init(multi_session *session)
{
    memset(session, 0, sizeof(*session));
    session->fd = -1;
    session->line_start = 1;
}

static void multi_session_close(multi_session *sessions, int idx)
{
    sessions[idx].fd = wcat_close_quiet(sessions[idx].fd);
    sessions[idx].id = 0;
    sessions[idx].name[0] = '\0';
    sessions[idx].host[0] = '\0';
    sessions[idx].port[0] = '\0';
    sessions[idx].rx_bytes = 0;
    sessions[idx].tx_bytes = 0;
    sessions[idx].line_start = 1;
}

static int multi_find_by_id(multi_session *sessions, int max_sessions, unsigned int id)
{
    int i;

    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0 && sessions[i].id == id) {
            return i;
        }
    }
    return -1;
}

static unsigned int multi_first_session_id(multi_session *sessions, int max_sessions)
{
    int i;

    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0) {
            return sessions[i].id;
        }
    }
    return 0;
}

static unsigned int multi_next_session_id(multi_session *sessions, int max_sessions,
                                          unsigned int active_id)
{
    int active_idx = multi_find_by_id(sessions, max_sessions, active_id);
    int i;

    if (active_idx < 0) {
        return multi_first_session_id(sessions, max_sessions);
    }
    for (i = active_idx + 1; i < max_sessions; i++) {
        if (sessions[i].fd >= 0) {
            return sessions[i].id;
        }
    }
    return multi_first_session_id(sessions, max_sessions);
}

static unsigned int multi_prev_session_id(multi_session *sessions, int max_sessions,
                                          unsigned int active_id)
{
    int active_idx = multi_find_by_id(sessions, max_sessions, active_id);
    int i;

    if (active_idx < 0) {
        return multi_first_session_id(sessions, max_sessions);
    }
    for (i = active_idx - 1; i >= 0; i--) {
        if (sessions[i].fd >= 0) {
            return sessions[i].id;
        }
    }
    for (i = max_sessions - 1; i >= 0; i--) {
        if (sessions[i].fd >= 0) {
            return sessions[i].id;
        }
    }
    return 0;
}

static const char *multi_session_label(const multi_session *session)
{
    return session->name[0] != '\0' ? session->name : "peer";
}

static const char *multi_skip_space(const char *s)
{
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    return s;
}

static size_t multi_line_trim_len(const char *line, size_t len)
{
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        len--;
    }
    return len;
}

static int multi_parse_id_arg(const char *arg, unsigned int *id, const char **rest)
{
    char *end = NULL;
    unsigned long parsed;

    arg = multi_skip_space(arg);
    if (*arg < '0' || *arg > '9') {
        return -1;
    }
    parsed = strtoul(arg, &end, 10);
    if (parsed == 0 || parsed > UINT_MAX) {
        return -1;
    }
    if (rest != NULL) {
        *rest = multi_skip_space(end);
    }
    *id = (unsigned int)parsed;
    return 0;
}

static void multi_print_prompt(unsigned int active_id)
{
    const int color = isatty(STDERR_FILENO);
    const char *reset = color ? "\033[0m" : "";
    const char *bold = color ? "\033[1m" : "";
    const char *cyan = color ? "\033[36m" : "";
    const char *yellow = color ? "\033[33m" : "";
    const char *dim = color ? "\033[2m" : "";

    if (active_id == 0) {
        dprintf(STDERR_FILENO, "%s%swcat%s[%sstandby%s]> %s",
                bold, cyan, reset, dim, reset, reset);
    } else {
        dprintf(STDERR_FILENO, "%s%swcat%s[%s*%u%s]> %s",
                bold, cyan, reset, yellow, active_id, reset, reset);
    }
}

static void multi_print_help(void)
{
    const int color = isatty(STDERR_FILENO);
    const char *reset = color ? "\033[0m" : "";
    const char *bold = color ? "\033[1m" : "";
    const char *cyan = color ? "\033[36m" : "";
    const char *green = color ? "\033[32m" : "";
    const char *yellow = color ? "\033[33m" : "";
    const char *dim = color ? "\033[2m" : "";

    dprintf(STDERR_FILENO,
            "\n"
            "%s................................................%s\n"
            "%s%scontrol plane%s  %sstdin targets the active peer%s\n"
            "  %s.%s %speer%s      %s:sessions%s/:s  %s:use N%s/:u  %s:next%s/:n  %s:prev%s/:p\n"
            "  %s.%s %sdetail%s    %s:info N%s/:i   %s:rename N NAME%s\n"
            "  %s.%s %saction%s    %s:attach [N]%s/:at  %s:send N CMD%s  %s:all CMD%s/:a  %s:kill N%s/:k\n"
            "  %s.%s %ssystem%s    %s:clear%s/:c    %s:help%s      %s:quit%s/:q  %sCtrl-]%s/%sback%s/%s:back%s/%s:detach%s\n"
            "%s................................................%s\n\n",
            dim, reset,
            bold, cyan, reset, dim, reset,
            green, reset, dim, reset, green, reset, green, reset, green, reset, green, reset,
            green, reset, dim, reset, green, reset, green, reset,
            yellow, reset, dim, reset, yellow, reset, yellow, reset, yellow, reset, yellow, reset,
            cyan, reset, dim, reset, green, reset, green, reset, yellow, reset,
            yellow, reset, yellow, reset, yellow, reset, yellow, reset,
            dim, reset);
}

static void multi_print_sessions(multi_session *sessions, int max_sessions, unsigned int active_id)
{
    const int color = isatty(STDERR_FILENO);
    const char *reset = color ? "\033[0m" : "";
    const char *bold = color ? "\033[1m" : "";
    const char *cyan = color ? "\033[36m" : "";
    const char *green = color ? "\033[32m" : "";
    const char *yellow = color ? "\033[33m" : "";
    const char *dim = color ? "\033[2m" : "";
    int count = 0;
    int i;

    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0) {
            count++;
        }
    }

    dprintf(STDERR_FILENO,
            "\n%s................................................%s\n"
            "%s%speers%s %s%d/%d%s",
            dim, reset,
            bold, cyan, reset, dim, count, max_sessions, reset);
    if (count == 0) {
        dprintf(STDERR_FILENO,
                "\n  %s.%s %sidle%s\n"
                "%s................................................%s\n\n",
                dim, reset, dim, reset,
                dim, reset);
        return;
    }

    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0) {
            const int active = sessions[i].id == active_id;

            dprintf(STDERR_FILENO, "\n  %s.%s %s%c%-3u%s %s%-6s%s %s%s%s %s%s:%s%s",
                    active ? yellow : green,
                    reset,
                    active ? yellow : green,
                    active ? '*' : '#',
                    sessions[i].id,
                    reset,
                    active ? yellow : green,
                    active ? "active" : "ready",
                    reset,
                    active ? bold : dim,
                    multi_session_label(&sessions[i]),
                    reset,
                    dim,
                    sessions[i].host, sessions[i].port,
                    reset);
        }
    }
    dprintf(STDERR_FILENO, "\n%s................................................%s\n", dim, reset);
}

static void multi_set_active_session(multi_session *sessions, int max_sessions,
                                     unsigned int *active_id, unsigned int id)
{
    const int color = isatty(STDERR_FILENO);
    const char *reset = color ? "\033[0m" : "";
    const char *green = color ? "\033[32m" : "";
    const char *red = color ? "\033[31m" : "";

    if (id != 0 && multi_find_by_id(sessions, max_sessions, id) >= 0) {
        *active_id = id;
        dprintf(STDERR_FILENO, "%sactive%s session %u\n",
                green, reset, *active_id);
    } else {
        dprintf(STDERR_FILENO, "%serror%s no sessions\n", red, reset);
    }
    multi_print_prompt(*active_id);
}

static void multi_print_info(multi_session *sessions, int max_sessions,
                             unsigned int active_id, unsigned int id)
{
    const int color = isatty(STDERR_FILENO);
    const char *reset = color ? "\033[0m" : "";
    const char *bold = color ? "\033[1m" : "";
    const char *cyan = color ? "\033[36m" : "";
    const char *green = color ? "\033[32m" : "";
    const char *yellow = color ? "\033[33m" : "";
    const char *dim = color ? "\033[2m" : "";
    int idx = multi_find_by_id(sessions, max_sessions, id);

    if (idx < 0) {
        dprintf(STDERR_FILENO, "%serror%s no such session\n",
                color ? "\033[31m" : "", reset);
        return;
    }
    dprintf(STDERR_FILENO,
            "\n%s................................................%s\n"
            "%s%ssession%s %s%u%s  %s%s%s\n"
            "  %s.%s %sstate%s    %s%s%s\n"
            "  %s.%s %speer%s     %s:%s\n"
            "  %s.%s %straffic%s  rx=%zu tx=%zu\n"
            "%s................................................%s\n\n",
            dim, reset,
            bold, cyan, reset, yellow, sessions[idx].id, reset,
            bold, multi_session_label(&sessions[idx]), reset,
            active_id == id ? yellow : green, reset, dim, reset,
            active_id == id ? yellow : green, active_id == id ? "active" : "ready", reset,
            green, reset, dim, reset, sessions[idx].host, sessions[idx].port,
            cyan, reset, dim, reset, sessions[idx].rx_bytes, sessions[idx].tx_bytes,
            dim, reset);
}

static int multi_send_line(multi_session *session, const char *line, size_t len)
{
    if (session->fd < 0) {
        return -1;
    }
    if (wcat_full_write(session->fd, line, len) != (ssize_t)len) {
        return -1;
    }
    session->tx_bytes += len;
    return 0;
}

static void multi_broadcast(multi_session *sessions, int max_sessions,
                            const char *line, size_t len)
{
    int i;

    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0 && multi_send_line(&sessions[i], line, len) < 0) {
            wcat_log(WCAT_LOG_WARN, "multi_drop", "dropping failed session %u",
                     sessions[i].id);
            multi_session_close(sessions, i);
        }
    }
}

static void multi_handle_input_line(multi_session *sessions, int max_sessions,
                                    unsigned int *active_id,
                                    unsigned int *attached_id,
                                    const char *line, size_t len)
{
    if (len > 0 && line[0] == ':') {
        char command[WCAT_MULTI_INPUT + 1];
        size_t command_len = multi_line_trim_len(line, len);

        memcpy(command, line, command_len);
        command[command_len] = '\0';

        if (strcmp(command, ":help") == 0) {
            multi_print_help();
            multi_print_prompt(*active_id);
            return;
        }
        if (strcmp(command, ":sessions") == 0 || strcmp(command, ":s") == 0) {
            multi_print_sessions(sessions, max_sessions, *active_id);
            multi_print_prompt(*active_id);
            return;
        }
        if (strcmp(command, ":quit") == 0 || strcmp(command, ":q") == 0) {
            wcat_stop = 1;
            return;
        }
        if (strcmp(command, ":detach") == 0) {
            if (attached_id != NULL) {
                *attached_id = 0;
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strcmp(command, ":next") == 0 || strcmp(command, ":n") == 0) {
            multi_set_active_session(sessions, max_sessions, active_id,
                                     multi_next_session_id(sessions, max_sessions, *active_id));
            return;
        }
        if (strcmp(command, ":prev") == 0 || strcmp(command, ":p") == 0) {
            multi_set_active_session(sessions, max_sessions, active_id,
                                     multi_prev_session_id(sessions, max_sessions, *active_id));
            return;
        }
        if (strcmp(command, ":clear") == 0 || strcmp(command, ":c") == 0) {
            dprintf(STDERR_FILENO, "\033[2J\033[H");
            multi_print_prompt(*active_id);
            return;
        }
        if (strncmp(command, ":use ", 5) == 0 || strncmp(command, ":u ", 3) == 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *green = color ? "\033[32m" : "";
            const char *red = color ? "\033[31m" : "";
            unsigned int id;
            const char *arg = command[1] == 'u' && command[2] == ' ' ? command + 3 : command + 5;

            if (multi_parse_id_arg(arg, &id, NULL) == 0 &&
                multi_find_by_id(sessions, max_sessions, id) >= 0) {
                *active_id = id;
                dprintf(STDERR_FILENO, "%sactive%s session %u\n",
                        green, reset, *active_id);
            } else {
                dprintf(STDERR_FILENO, "%serror%s no such session\n",
                        red, reset);
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strcmp(command, ":attach") == 0 ||
            strncmp(command, ":attach ", 8) == 0 ||
            strncmp(command, ":at ", 4) == 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *green = color ? "\033[32m" : "";
            const char *red = color ? "\033[31m" : "";
            unsigned int id = *active_id;
            const char *arg = NULL;

            if (strncmp(command, ":attach ", 8) == 0) {
                arg = command + 8;
            } else if (strncmp(command, ":at ", 4) == 0) {
                arg = command + 4;
            }
            if (arg != NULL && multi_parse_id_arg(arg, &id, NULL) < 0) {
                id = 0;
            }
            if (attached_id != NULL && id != 0 &&
                multi_find_by_id(sessions, max_sessions, id) >= 0) {
                *active_id = id;
                *attached_id = id;
                dprintf(STDERR_FILENO,
                        "%sattached%s session %u; press Ctrl-] to detach\n",
                        green, reset, id);
            } else {
                dprintf(STDERR_FILENO, "%serror%s no such session\n",
                        red, reset);
                multi_print_prompt(*active_id);
            }
            return;
        }
        if (strncmp(command, ":info ", 6) == 0 || strncmp(command, ":i ", 3) == 0) {
            unsigned int id;
            const char *arg = command[1] == 'i' && command[2] == ' ' ? command + 3 : command + 6;

            if (multi_parse_id_arg(arg, &id, NULL) == 0) {
                multi_print_info(sessions, max_sessions, *active_id, id);
            } else {
                const int color = isatty(STDERR_FILENO);
                const char *reset = color ? "\033[0m" : "";
                const char *red = color ? "\033[31m" : "";

                dprintf(STDERR_FILENO, "%serror%s invalid session id\n",
                        red, reset);
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strncmp(command, ":rename ", 8) == 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *green = color ? "\033[32m" : "";
            const char *red = color ? "\033[31m" : "";
            unsigned int id;
            const char *name = NULL;
            int idx = -1;

            if (multi_parse_id_arg(command + 8, &id, &name) == 0) {
                idx = multi_find_by_id(sessions, max_sessions, id);
            }
            if (idx >= 0 && name != NULL && *name != '\0') {
                snprintf(sessions[idx].name, sizeof(sessions[idx].name), "%s", name);
                dprintf(STDERR_FILENO, "%srenamed%s session %u\n",
                        green, reset, id);
            } else {
                dprintf(STDERR_FILENO, "%serror%s invalid rename target\n",
                        red, reset);
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strncmp(command, ":kill ", 6) == 0 || strncmp(command, ":k ", 3) == 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *green = color ? "\033[32m" : "";
            const char *yellow = color ? "\033[33m" : "";
            const char *red = color ? "\033[31m" : "";
            unsigned int id;
            const char *arg = command[1] == 'k' && command[2] == ' ' ? command + 3 : command + 6;
            int idx = -1;

            if (multi_parse_id_arg(arg, &id, NULL) == 0) {
                idx = multi_find_by_id(sessions, max_sessions, id);
            }
            if (idx >= 0) {
                char host[sizeof(sessions[idx].host)];
                char port[sizeof(sessions[idx].port)];

                snprintf(host, sizeof(host), "%s", sessions[idx].host);
                snprintf(port, sizeof(port), "%s", sessions[idx].port);
                multi_session_close(sessions, idx);
                if (*active_id == id) {
                    *active_id = multi_first_session_id(sessions, max_sessions);
                }
                dprintf(STDERR_FILENO, "%skilled%s session %u %s%s:%s%s\n",
                        yellow, reset, id, green, host, port, reset);
                if (*active_id != 0) {
                    dprintf(STDERR_FILENO, "%sactive%s session %u\n",
                            green, reset, *active_id);
                }
            } else {
                dprintf(STDERR_FILENO, "%serror%s no such session\n",
                        red, reset);
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strncmp(command, ":send ", 6) == 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *red = color ? "\033[31m" : "";
            unsigned int id;
            const char *payload = NULL;
            int idx = -1;

            if (multi_parse_id_arg(command + 6, &id, &payload) == 0) {
                idx = multi_find_by_id(sessions, max_sessions, id);
            }
            if (idx >= 0 && payload != NULL && *payload != '\0') {
                if (multi_send_line(&sessions[idx], payload, strlen(payload)) < 0 ||
                    multi_send_line(&sessions[idx], "\n", 1) < 0) {
                    dprintf(STDERR_FILENO, "%serror%s send failed\n", red, reset);
                    multi_session_close(sessions, idx);
                    if (*active_id == id) {
                        *active_id = multi_first_session_id(sessions, max_sessions);
                    }
                }
            } else {
                dprintf(STDERR_FILENO, "%serror%s invalid send target\n",
                        red, reset);
            }
            multi_print_prompt(*active_id);
            return;
        }
        if (strncmp(command, ":all ", 5) == 0 || strncmp(command, ":a ", 3) == 0) {
            const char *payload = line[1] == 'a' && line[2] == ' ' ? line + 3 : line + 5;
            size_t payload_len = len - (size_t)(payload - line);

            multi_broadcast(sessions, max_sessions, payload, payload_len);
            multi_print_prompt(*active_id);
            return;
        }
        {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *red = color ? "\033[31m" : "";

            dprintf(STDERR_FILENO, "%serror%s unknown multi command\n",
                    red, reset);
        }
        multi_print_help();
        multi_print_prompt(*active_id);
        return;
    }
    if (*active_id == 0) {
        const int color = isatty(STDERR_FILENO);
        const char *reset = color ? "\033[0m" : "";
        const char *red = color ? "\033[31m" : "";

        dprintf(STDERR_FILENO, "%serror%s no active session\n",
                red, reset);
        multi_print_prompt(*active_id);
        return;
    }
    {
        int idx = multi_find_by_id(sessions, max_sessions, *active_id);

        if (idx < 0 || multi_send_line(&sessions[idx], line, len) < 0) {
            const int color = isatty(STDERR_FILENO);
            const char *reset = color ? "\033[0m" : "";
            const char *red = color ? "\033[31m" : "";

            dprintf(STDERR_FILENO, "%serror%s active session unavailable\n",
                    red, reset);
            if (idx >= 0) {
                multi_session_close(sessions, idx);
            }
            *active_id = multi_first_session_id(sessions, max_sessions);
            multi_print_prompt(*active_id);
        }
    }
}

static void multi_handle_stdin(multi_session *sessions, int max_sessions,
                               unsigned int *active_id,
                               unsigned int *attached_id,
                               char *input, size_t *input_len)
{
    ssize_t n;

    do {
        n = read(STDIN_FILENO, input + *input_len, WCAT_MULTI_INPUT - *input_len);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) {
        return;
    }
    *input_len += (size_t)n;
    while (*input_len > 0) {
        char *nl = memchr(input, '\n', *input_len);
        size_t line_len;

        if (nl == NULL) {
            if (*input_len == WCAT_MULTI_INPUT) {
                multi_handle_input_line(sessions, max_sessions, active_id,
                                        attached_id,
                                        input, *input_len);
                *input_len = 0;
            }
            return;
        }
        line_len = (size_t)(nl - input) + 1;
        multi_handle_input_line(sessions, max_sessions, active_id, attached_id,
                                input, line_len);
        memmove(input, input + line_len, *input_len - line_len);
        *input_len -= line_len;
    }
}

static void multi_redraw_input(unsigned int active_id, const char *input,
                               size_t input_len, size_t cursor)
{
    dprintf(STDERR_FILENO, "\r\033[2K");
    multi_print_prompt(active_id);
    if (input_len > 0) {
        (void)wcat_full_write(STDERR_FILENO, input, input_len);
    }
    if (cursor < input_len) {
        dprintf(STDERR_FILENO, "\033[%zuD", input_len - cursor);
    }
}

static void multi_history_save(char history[WCAT_MULTI_HISTORY][WCAT_MULTI_INPUT],
                               int *history_count, const char *line, size_t len)
{
    len = multi_line_trim_len(line, len);
    if (len == 0) {
        return;
    }
    if (len >= WCAT_MULTI_INPUT) {
        len = WCAT_MULTI_INPUT - 1;
    }
    if (*history_count > 0 &&
        strlen(history[*history_count - 1]) == len &&
        memcmp(history[*history_count - 1], line, len) == 0) {
        return;
    }
    if (*history_count == WCAT_MULTI_HISTORY) {
        memmove(history[0], history[1],
                (WCAT_MULTI_HISTORY - 1) * sizeof(history[0]));
        (*history_count)--;
    }
    memcpy(history[*history_count], line, len);
    history[*history_count][len] = '\0';
    (*history_count)++;
}

static void multi_history_load(unsigned int active_id,
                               char history[WCAT_MULTI_HISTORY][WCAT_MULTI_INPUT],
                               int history_count, int *history_pos,
                               char *input, size_t *input_len, size_t *cursor,
                               int direction)
{
    if (history_count == 0) {
        return;
    }
    if (direction < 0) {
        if (*history_pos < 0) {
            *history_pos = history_count - 1;
        } else if (*history_pos > 0) {
            (*history_pos)--;
        }
    } else {
        if (*history_pos < 0) {
            return;
        }
        if (*history_pos + 1 < history_count) {
            (*history_pos)++;
        } else {
            *history_pos = -1;
            *input_len = 0;
            *cursor = 0;
            multi_redraw_input(active_id, input, *input_len, *cursor);
            return;
        }
    }
    *input_len = strlen(history[*history_pos]);
    memcpy(input, history[*history_pos], *input_len);
    *cursor = *input_len;
    multi_redraw_input(active_id, input, *input_len, *cursor);
}

static void multi_handle_input_key(unsigned int active_id,
                                   char history[WCAT_MULTI_HISTORY][WCAT_MULTI_INPUT],
                                   int history_count, int *history_pos,
                                   char *input, size_t *input_len, size_t *cursor,
                                   char key)
{
    switch (key) {
    case 'A':
        multi_history_load(active_id, history, history_count, history_pos,
                           input, input_len, cursor, -1);
        break;
    case 'B':
        multi_history_load(active_id, history, history_count, history_pos,
                           input, input_len, cursor, 1);
        break;
    case 'D':
        if (*cursor > 0) {
            (*cursor)--;
            dprintf(STDERR_FILENO, "\033[D");
        }
        break;
    case 'C':
        if (*cursor < *input_len) {
            (*cursor)++;
            dprintf(STDERR_FILENO, "\033[C");
        }
        break;
    case 'H':
    case 'h':
        if (*cursor > 0) {
            dprintf(STDERR_FILENO, "\033[%zuD", *cursor);
            *cursor = 0;
        }
        break;
    case 'F':
    case 'f':
        if (*cursor < *input_len) {
            dprintf(STDERR_FILENO, "\033[%zuC", *input_len - *cursor);
            *cursor = *input_len;
        }
        break;
    default:
        break;
    }
}

static void multi_handle_interactive_stdin(multi_session *sessions, int max_sessions,
                                           unsigned int *active_id,
                                           unsigned int *attached_id,
                                           char *input, size_t *input_len,
                                           size_t *cursor, int *esc_state,
                                           char history[WCAT_MULTI_HISTORY][WCAT_MULTI_INPUT],
                                           int *history_count, int *history_pos)
{
    unsigned char buf[128];
    ssize_t n;
    ssize_t i;

    do {
        n = read(STDIN_FILENO, buf, sizeof(buf));
    } while (n < 0 && errno == EINTR);
    if (n <= 0) {
        return;
    }

    for (i = 0; i < n; i++) {
        unsigned char ch = buf[i];

        if (*esc_state == 1) {
            if (ch == '[') {
                *esc_state = 2;
            } else if (ch == 'O') {
                *esc_state = 3;
            } else {
                *esc_state = 0;
            }
            continue;
        }
        if (*esc_state == 2) {
            if (ch == 'A' || ch == 'B' || ch == 'C' || ch == 'D' ||
                ch == 'H' || ch == 'F') {
                multi_handle_input_key(*active_id, history, *history_count,
                                       history_pos, input, input_len, cursor,
                                       (char)ch);
                *esc_state = 0;
            } else if (ch >= '0' && ch <= '9') {
                *esc_state = 100 + ch;
            } else {
                *esc_state = 0;
            }
            continue;
        }
        if (*esc_state == 3) {
            if (ch == 'w') {
                multi_handle_input_key(*active_id, history, *history_count,
                                       history_pos, input, input_len, cursor, 'H');
            } else if (ch == 'q') {
                multi_handle_input_key(*active_id, history, *history_count,
                                       history_pos, input, input_len, cursor, 'F');
            } else {
                multi_handle_input_key(*active_id, history, *history_count,
                                       history_pos, input, input_len, cursor,
                                       (char)ch);
            }
            *esc_state = 0;
            continue;
        }
        if (*esc_state >= 100) {
            int digit = *esc_state - 100;

            if (ch == '~') {
                if (digit == '1' || digit == '7') {
                    multi_handle_input_key(*active_id, history, *history_count,
                                           history_pos, input, input_len, cursor, 'H');
                } else if (digit == '4' || digit == '8') {
                    multi_handle_input_key(*active_id, history, *history_count,
                                           history_pos, input, input_len, cursor, 'F');
                }
            }
            *esc_state = ch == '~' ? 0 : 99;
            continue;
        }
        if (*esc_state == 99) {
            if ((ch >= 'A' && ch <= 'Z') || ch == '~') {
                *esc_state = 0;
            }
            continue;
        }

        if (ch == '\033') {
            *esc_state = 1;
        } else if (ch == '\r' || ch == '\n') {
            if (*input_len < WCAT_MULTI_INPUT) {
                input[*input_len] = '\n';
                (*input_len)++;
            }
            dprintf(STDERR_FILENO, "\n");
            multi_history_save(history, history_count, input, *input_len);
            *history_pos = -1;
            multi_handle_input_line(sessions, max_sessions, active_id, attached_id,
                                    input, *input_len);
            *input_len = 0;
            *cursor = 0;
        } else if (ch == '\b' || ch == 127) {
            if (*cursor > 0) {
                memmove(input + *cursor - 1, input + *cursor, *input_len - *cursor);
                (*input_len)--;
                (*cursor)--;
                *history_pos = -1;
                multi_redraw_input(*active_id, input, *input_len, *cursor);
            }
        } else if ((ch == '\t' || (ch >= 32 && ch < 127)) &&
                   *input_len < WCAT_MULTI_INPUT) {
            memmove(input + *cursor + 1, input + *cursor, *input_len - *cursor);
            input[*cursor] = (char)ch;
            (*input_len)++;
            (*cursor)++;
            *history_pos = -1;
            multi_redraw_input(*active_id, input, *input_len, *cursor);
        }
    }
}

static int multi_attached_detach_match(const char *line, size_t len, int *exact)
{
    static const char *words[] = {"back", ":back", ":detach"};
    size_t i;

    *exact = 0;
    for (i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        size_t word_len = strlen(words[i]);

        if (len <= word_len && memcmp(words[i], line, len) == 0) {
            if (len == word_len) {
                *exact = 1;
            }
            return 1;
        }
    }
    return 0;
}

static int multi_looks_http_request(const unsigned char *buf, size_t len)
{
    static const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
        "PATCH ", "TRACE ", "CONNECT ", "PRI * HTTP/2.0"
    };
    size_t i;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t method_len = strlen(methods[i]);

        if (len >= method_len && memcmp(buf, methods[i], method_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static void multi_echo_pending_append(char *pending, size_t *pending_len,
                                      const char *buf, size_t len)
{
    if (len > WCAT_MULTI_ECHO_PENDING - *pending_len) {
        size_t drop = len - (WCAT_MULTI_ECHO_PENDING - *pending_len);

        if (drop >= *pending_len) {
            *pending_len = 0;
        } else {
            memmove(pending, pending + drop, *pending_len - drop);
            *pending_len -= drop;
        }
    }
    if (len > WCAT_MULTI_ECHO_PENDING) {
        buf += len - WCAT_MULTI_ECHO_PENDING;
        len = WCAT_MULTI_ECHO_PENDING;
    }
    memcpy(pending + *pending_len, buf, len);
    *pending_len += len;
}

static int multi_write_attached_output(multi_session *session, const unsigned char *buf,
                                       size_t len, char *echo_pending,
                                       size_t *echo_pending_len)
{
    size_t i;

    session->line_start = 1;
    for (i = 0; i < len; i++) {
        if (*echo_pending_len > 0) {
            if (buf[i] == (unsigned char)echo_pending[0]) {
                memmove(echo_pending, echo_pending + 1, *echo_pending_len - 1);
                (*echo_pending_len)--;
                continue;
            }
            if (buf[i] == '\r' && echo_pending[0] == '\n') {
                continue;
            }
            *echo_pending_len = 0;
        }
        if (wcat_full_write(STDOUT_FILENO, buf + i, 1) != 1) {
            return -1;
        }
    }
    return 0;
}

static void multi_handle_attached_stdin(multi_session *sessions, int max_sessions,
                                        unsigned int *active_id,
                                        unsigned int *attached_id,
                                        char *attached_line,
                                        size_t *attached_line_len,
                                        int *attached_line_held,
                                        char *echo_pending,
                                        size_t *echo_pending_len)
{
    unsigned char buf[512];
    ssize_t n;
    ssize_t i;
    int idx;

    idx = multi_find_by_id(sessions, max_sessions, *attached_id);
    if (idx < 0) {
        *attached_id = 0;
        *active_id = multi_first_session_id(sessions, max_sessions);
        dprintf(STDERR_FILENO, "\n");
        multi_print_prompt(*active_id);
        return;
    }

    do {
        n = read(STDIN_FILENO, buf, sizeof(buf));
    } while (n < 0 && errno == EINTR);
    if (n <= 0) {
        return;
    }

    for (i = 0; i < n; i++) {
        unsigned char ch = buf[i];

        if (ch == 0x1d) {
            *attached_id = 0;
            *attached_line_len = 0;
            *attached_line_held = 1;
            *echo_pending_len = 0;
            dprintf(STDERR_FILENO, "\n");
            multi_print_prompt(*active_id);
            continue;
        }

        if (ch == '\b' || ch == 127) {
            if (*attached_line_len > 0) {
                (*attached_line_len)--;
                if (!*attached_line_held) {
                    (void)multi_send_line(&sessions[idx], (const char *)&ch, 1);
                    multi_echo_pending_append(echo_pending, echo_pending_len,
                                              (const char *)&ch, 1);
                }
            }
            dprintf(STDERR_FILENO, "\b \b");
            continue;
        }

        if (ch == '\r' || ch == '\n') {
            int detach = 0;
            int exact = 0;

            attached_line[*attached_line_len] = '\0';
            if (*attached_line_held &&
                multi_attached_detach_match(attached_line, *attached_line_len, &exact) &&
                exact) {
                detach = 1;
            }
            if (detach) {
                *attached_id = 0;
                *attached_line_len = 0;
                *attached_line_held = 1;
                *echo_pending_len = 0;
                dprintf(STDERR_FILENO, "\n");
                multi_print_prompt(*active_id);
                continue;
            }
            if (*attached_line_held && *attached_line_len > 0) {
                (void)multi_send_line(&sessions[idx], attached_line, *attached_line_len);
                multi_echo_pending_append(echo_pending, echo_pending_len,
                                          attached_line, *attached_line_len);
            }
            *attached_line_len = 0;
            *attached_line_held = 1;
            (void)multi_send_line(&sessions[idx], "\n", 1);
            multi_echo_pending_append(echo_pending, echo_pending_len, "\n", 1);
            dprintf(STDERR_FILENO, "\n");
            continue;
        }

        if (*attached_line_len + 1 < WCAT_MULTI_INPUT &&
            (ch == '\t' || (ch >= 32 && ch < 127))) {
            int exact = 0;

            attached_line[*attached_line_len] = (char)ch;
            (*attached_line_len)++;
            if (*attached_line_held &&
                !multi_attached_detach_match(attached_line, *attached_line_len, &exact)) {
                (void)multi_send_line(&sessions[idx], attached_line, *attached_line_len);
                multi_echo_pending_append(echo_pending, echo_pending_len,
                                          attached_line, *attached_line_len);
                *attached_line_held = 0;
            } else if (!*attached_line_held) {
                (void)multi_send_line(&sessions[idx], (const char *)&ch, 1);
                multi_echo_pending_append(echo_pending, echo_pending_len,
                                          (const char *)&ch, 1);
            }
        } else if (*attached_id != 0) {
            (void)multi_send_line(&sessions[idx], (const char *)&ch, 1);
            multi_echo_pending_append(echo_pending, echo_pending_len,
                                      (const char *)&ch, 1);
        }
        if (ch >= 32 && ch < 127) {
            (void)wcat_full_write(STDERR_FILENO, &ch, 1);
        }
    }
}

static int multi_write_output(multi_session *session, const unsigned char *buf,
                              size_t len, int raw)
{
    size_t i = 0;

    if (raw) {
        session->line_start = 1;
        return wcat_full_write(STDOUT_FILENO, buf, len) == (ssize_t)len ? 0 : -1;
    }

    while (i < len) {
        size_t start = i;

        if (session->line_start) {
            char prefix[192];
            int n = snprintf(prefix, sizeof(prefix), "[session%u %s:%s] ",
                             session->id, session->host, session->port);

            if (n < 0 || (size_t)n >= sizeof(prefix) ||
                wcat_full_write(STDOUT_FILENO, prefix, (size_t)n) != n) {
                return -1;
            }
            session->line_start = 0;
        }
        while (i < len && buf[i] != '\n') {
            i++;
        }
        if (i < len && buf[i] == '\n') {
            i++;
            session->line_start = 1;
        }
        if (wcat_full_write(STDOUT_FILENO, buf + start, i - start) != (ssize_t)(i - start)) {
            return -1;
        }
    }
    return 0;
}

static int run_multi_listen(const wcat_config *cfg)
{
    int listener;
    multi_session sessions[WCAT_MULTI_LIMIT];
    struct pollfd pfds[WCAT_MULTI_LIMIT + 2];
    unsigned char buf[WCAT_MULTI_BUFSIZE];
    char input[WCAT_MULTI_INPUT];
    size_t input_len = 0;
    size_t input_cursor = 0;
    char input_history[WCAT_MULTI_HISTORY][WCAT_MULTI_INPUT];
    char attached_line[WCAT_MULTI_INPUT];
    char echo_pending[WCAT_MULTI_ECHO_PENDING];
    size_t attached_line_len = 0;
    size_t echo_pending_len = 0;
    int attached_line_held = 1;
    int input_history_count = 0;
    int input_history_pos = -1;
    struct termios saved_termios;
    int restore_termios = 0;
    int interactive_input = 0;
    int esc_state = 0;
    int max_sessions = cfg->broker_max_clients;
    unsigned int next_id = 1;
    unsigned int active_id = 0;
    unsigned int attached_id = 0;
    int result = 0;
    int i;

    if (max_sessions < 1 || max_sessions > WCAT_MULTI_LIMIT) {
        wcat_log(WCAT_LOG_ERROR, "multi_config", "invalid multi session limit");
        return 2;
    }
    for (i = 0; i < WCAT_MULTI_LIMIT; i++) {
        multi_session_init(&sessions[i]);
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
        wcat_log_errno("listen", "multi listen failed");
        return 1;
    }
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        struct termios raw = saved_termios;

        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 1;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
            restore_termios = 1;
            interactive_input = 1;
        }
    }
    wcat_log(WCAT_LOG_INFO, "multi_listen", "multi listener ready; use :help for commands");
    if (interactive_input) {
        multi_redraw_input(active_id, input, input_len, input_cursor);
    } else {
        multi_print_prompt(active_id);
    }

    while (!wcat_stop) {
        int nfds = 0;
        int rc;

        pfds[nfds].fd = listener;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
        pfds[nfds].fd = STDIN_FILENO;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
        for (i = 0; i < max_sessions; i++) {
            if (sessions[i].fd >= 0) {
                pfds[nfds].fd = sessions[i].fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;
            }
        }
        rc = poll(pfds, (nfds_t)nfds, cfg->timeout_ms >= 0 ? cfg->timeout_ms : 250);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            wcat_log_errno("multi_poll", "multi poll failed");
            result = 1;
            break;
        }
        if (rc == 0) {
            continue;
        }
        if ((pfds[0].revents & POLLIN) != 0) {
            char host[128] = "";
            char port[32] = "";
            int fd = wcat_accept(listener, host, sizeof(host), port, sizeof(port));

            if (fd >= 0) {
                if (!wcat_access_check_fd(cfg, fd)) {
                    (void)wcat_close_quiet(fd);
                } else {
                    for (i = 0; i < max_sessions && sessions[i].fd >= 0; i++) {
                    }
                    if (i == max_sessions) {
                        wcat_log(WCAT_LOG_WARN, "multi_full", "multi session limit reached");
                        (void)wcat_close_quiet(fd);
                    } else {
                        sessions[i].fd = fd;
                        sessions[i].id = next_id++;
                        sessions[i].line_start = 1;
                        snprintf(sessions[i].host, sizeof(sessions[i].host), "%s",
                                 host[0] != '\0' ? host : "peer");
                        snprintf(sessions[i].port, sizeof(sessions[i].port), "%s",
                                 port[0] != '\0' ? port : "0");
                        if (active_id == 0) {
                            active_id = sessions[i].id;
                        }
                        wcat_log(WCAT_LOG_INFO, "multi_join",
                                 "session %u accepted from %s:%s",
                                 sessions[i].id, sessions[i].host, sessions[i].port);
                        if (attached_id == 0) {
                            dprintf(STDERR_FILENO, "\n");
                            multi_print_prompt(active_id);
                        }
                    }
                }
            }
        }
        if ((pfds[1].revents & POLLIN) != 0) {
            if (attached_id != 0) {
                multi_handle_attached_stdin(sessions, max_sessions, &active_id, &attached_id,
                                            attached_line, &attached_line_len,
                                            &attached_line_held,
                                            echo_pending, &echo_pending_len);
            } else if (interactive_input) {
                multi_handle_interactive_stdin(sessions, max_sessions, &active_id,
                                               &attached_id, input, &input_len,
                                               &input_cursor, &esc_state,
                                               input_history, &input_history_count,
                                               &input_history_pos);
            } else {
                multi_handle_stdin(sessions, max_sessions, &active_id, &attached_id,
                                   input, &input_len);
            }
        }
        for (i = 0; i < max_sessions; i++) {
            int j;
            short revents = 0;

            if (sessions[i].fd < 0) {
                continue;
            }
            for (j = 2; j < nfds; j++) {
                if (pfds[j].fd == sessions[i].fd) {
                    revents = pfds[j].revents;
                    break;
                }
            }
            if (j == nfds) {
                continue;
            }
            if ((revents & (POLLERR | POLLNVAL)) != 0) {
                wcat_log(WCAT_LOG_INFO, "multi_leave", "session %u closed", sessions[i].id);
                if (attached_id == sessions[i].id) {
                    attached_id = 0;
                }
                multi_session_close(sessions, i);
                if (active_id != 0 && multi_find_by_id(sessions, max_sessions, active_id) < 0) {
                    active_id = multi_first_session_id(sessions, max_sessions);
                }
                if (attached_id == 0) {
                    multi_print_prompt(active_id);
                }
                continue;
            }
            if ((revents & (POLLIN | POLLHUP)) != 0) {
                ssize_t n;

                do {
                    n = read(sessions[i].fd, buf, sizeof(buf));
                } while (n < 0 && errno == EINTR);
                if (n <= 0) {
                    wcat_log(WCAT_LOG_INFO, "multi_leave", "session %u closed", sessions[i].id);
                    if (attached_id == sessions[i].id) {
                        attached_id = 0;
                    }
                    multi_session_close(sessions, i);
                    if (active_id != 0 && multi_find_by_id(sessions, max_sessions, active_id) < 0) {
                        active_id = multi_first_session_id(sessions, max_sessions);
                    }
                    if (attached_id == 0) {
                        multi_print_prompt(active_id);
                    }
                    continue;
                }
                if (sessions[i].rx_bytes == 0 &&
                    multi_looks_http_request(buf, (size_t)n)) {
                    int output_line_start;

                    if (interactive_input && attached_id == 0) {
                        dprintf(STDERR_FILENO, "\r\033[2K");
                    }
                    sessions[i].rx_bytes += (size_t)n;
                    if (cfg->hex) {
                        wcat_hexdump("multi", buf, (size_t)n);
                    }
                    if (attached_id == sessions[i].id) {
                        rc = multi_write_attached_output(&sessions[i], buf, (size_t)n,
                                                         echo_pending, &echo_pending_len);
                        attached_id = 0;
                    } else {
                        rc = multi_write_output(&sessions[i], buf, (size_t)n, 0);
                    }
                    if (rc < 0) {
                        result = 1;
                        wcat_stop = 1;
                        break;
                    }
                    output_line_start = sessions[i].line_start;
                    wcat_log(WCAT_LOG_INFO, "multi_leave", "session %u closed", sessions[i].id);
                    multi_session_close(sessions, i);
                    if (active_id != 0 &&
                        multi_find_by_id(sessions, max_sessions, active_id) < 0) {
                        active_id = multi_first_session_id(sessions, max_sessions);
                    }
                    if (interactive_input && attached_id == 0) {
                        if (!output_line_start) {
                            dprintf(STDERR_FILENO, "\n");
                        }
                        multi_redraw_input(active_id, input, input_len, input_cursor);
                    } else if (attached_id == 0) {
                        multi_print_prompt(active_id);
                    }
                    continue;
                }
                sessions[i].rx_bytes += (size_t)n;
                if (cfg->hex) {
                    wcat_hexdump("multi", buf, (size_t)n);
                }
                if (interactive_input && attached_id == 0) {
                    dprintf(STDERR_FILENO, "\r\033[2K");
                }
                if (attached_id == sessions[i].id) {
                    rc = multi_write_attached_output(&sessions[i], buf, (size_t)n,
                                                     echo_pending, &echo_pending_len);
                } else {
                    rc = multi_write_output(&sessions[i], buf, (size_t)n, 0);
                }
                if (rc < 0) {
                    result = 1;
                    wcat_stop = 1;
                    break;
                }
                if (interactive_input && attached_id == 0) {
                    if (!sessions[i].line_start) {
                        dprintf(STDERR_FILENO, "\n");
                    }
                    multi_redraw_input(active_id, input, input_len, input_cursor);
                }
            }
        }
    }
    for (i = 0; i < max_sessions; i++) {
        if (sessions[i].fd >= 0) {
            multi_session_close(sessions, i);
        }
    }
    if (restore_termios) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    }
    (void)wcat_close_quiet(listener);
    return result;
}

static int run_listen(const wcat_config *cfg)
{
    int listener;
    int rc = 0;

    if (cfg->multi) {
        return run_multi_listen(cfg);
    }

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
