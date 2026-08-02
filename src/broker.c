#include "access.h"
#include "broker.h"
#include "log.h"
#include "signalx.h"
#include "socketx.h"
#include "util.h"

#include <errno.h>
#include <stdlib.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define WCAT_BROKER_LIMIT 256
#define WCAT_BROKER_BUF 4096

typedef struct {
    int fd;
    unsigned int id;
    bool line_start;
    unsigned char *out;
    size_t out_len;
    size_t out_off;
} broker_client;

static void client_init(broker_client *client)
{
    client->fd = -1;
    client->id = 0;
    client->line_start = true;
    client->out = NULL;
    client->out_len = 0;
    client->out_off = 0;
}

static void drop_client(broker_client *clients, int idx)
{
    clients[idx].fd = wcat_close_quiet(clients[idx].fd);
    free(clients[idx].out);
    clients[idx].out = NULL;
    clients[idx].id = 0;
    clients[idx].line_start = true;
    clients[idx].out_len = 0;
    clients[idx].out_off = 0;
}

static int append_bytes(unsigned char **out, size_t *len, size_t *cap,
                        const unsigned char *buf, size_t n)
{
    unsigned char *next;
    size_t next_cap;

    if (n == 0) {
        return 0;
    }
    if (n > ((size_t)-1) - *len) {
        return -1;
    }
    if (*len + n <= *cap) {
        memcpy(*out + *len, buf, n);
        *len += n;
        return 0;
    }
    next_cap = *cap == 0 ? 128 : *cap;
    while (next_cap < *len + n) {
        if (next_cap > ((size_t)-1) / 2) {
            next_cap = *len + n;
            break;
        }
        next_cap *= 2;
    }
    next = realloc(*out, next_cap);
    if (next == NULL) {
        return -1;
    }
    *out = next;
    *cap = next_cap;
    memcpy(*out + *len, buf, n);
    *len += n;
    return 0;
}

static int append_cstr(unsigned char **out, size_t *len, size_t *cap, const char *s)
{
    return append_bytes(out, len, cap, (const unsigned char *)s, strlen(s));
}

static unsigned char *format_chat_message(broker_client *sender,
                                          const unsigned char *buf,
                                          size_t len, size_t *out_len)
{
    unsigned char *out = NULL;
    size_t cap = 0;
    size_t n = 0;
    size_t i;
    char prefix[32];

    for (i = 0; i < len; i++) {
        unsigned char c = buf[i];

        if (sender->line_start) {
            int written = snprintf(prefix, sizeof(prefix), "<client%u> ", sender->id);

            if (written < 0 || (size_t)written >= sizeof(prefix) ||
                append_bytes(&out, &n, &cap, (const unsigned char *)prefix,
                             (size_t)written) < 0) {
                free(out);
                return NULL;
            }
            sender->line_start = false;
        }
        if (c == '\n') {
            if (append_bytes(&out, &n, &cap, &c, 1) < 0) {
                free(out);
                return NULL;
            }
            sender->line_start = true;
        } else if (c == '\t') {
            if (append_bytes(&out, &n, &cap, &c, 1) < 0) {
                free(out);
                return NULL;
            }
        } else if (c == '\r') {
            if (append_cstr(&out, &n, &cap, "\\r") < 0) {
                free(out);
                return NULL;
            }
        } else if (c < 32 || c == 127) {
            char escaped[5];

            (void)snprintf(escaped, sizeof(escaped), "\\x%02x", c);
            if (append_cstr(&out, &n, &cap, escaped) < 0) {
                free(out);
                return NULL;
            }
        } else if (append_bytes(&out, &n, &cap, &c, 1) < 0) {
            free(out);
            return NULL;
        }
    }
    *out_len = n;
    return out;
}

static int queue_bytes(broker_client *client, const unsigned char *buf, size_t len,
                       size_t max_buffer)
{
    size_t pending = client->out_len - client->out_off;
    unsigned char *next;

    if (len > max_buffer || pending > max_buffer - len) {
        return -1;
    }
    if (client->out_off > 0 && pending > 0) {
        memmove(client->out, client->out + client->out_off, pending);
        client->out_len = pending;
        client->out_off = 0;
    } else if (pending == 0) {
        client->out_len = 0;
        client->out_off = 0;
    }
    next = realloc(client->out, client->out_len + len);
    if (next == NULL) {
        return -1;
    }
    client->out = next;
    memcpy(client->out + client->out_len, buf, len);
    client->out_len += len;
    return 0;
}

static int flush_client(broker_client *client)
{
    while (client->out_off < client->out_len) {
        ssize_t n = write(client->fd, client->out + client->out_off,
                          client->out_len - client->out_off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (n == 0) {
            return 0;
        }
        client->out_off += (size_t)n;
    }
    client->out_len = 0;
    client->out_off = 0;
    return 0;
}

int wcat_broker_run(const wcat_config *cfg)
{
    int listener;
    broker_client clients[WCAT_BROKER_LIMIT];
    struct pollfd pfds[WCAT_BROKER_LIMIT + 1];
    unsigned char buf[WCAT_BROKER_BUF];
    int max_clients = cfg->broker_max_clients;
    size_t max_buffer = (size_t)cfg->broker_buffer_bytes;
    unsigned int next_client_id = 1;
    int result = 0;
    int i;

    if (max_clients < 1 || max_clients > WCAT_BROKER_LIMIT) {
        wcat_log(WCAT_LOG_ERROR, "broker_config", "invalid broker client limit");
        return 2;
    }
    for (i = 0; i < WCAT_BROKER_LIMIT; i++) {
        client_init(&clients[i]);
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
        wcat_log_errno("listen", "broker listen failed");
        return 1;
    }
    if (cfg->unix_socket) {
        wcat_log(WCAT_LOG_INFO, "broker_listen", "broker listening on unix:%s", cfg->host);
    } else {
        wcat_log(WCAT_LOG_INFO, "broker_listen", "broker listening on %s:%s", cfg->host, cfg->port);
    }

    while (!wcat_stop) {
        int nfds = 1;
        int rc;
        pfds[0].fd = listener;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        for (i = 0; i < max_clients; i++) {
            if (clients[i].fd >= 0) {
                pfds[nfds].fd = clients[i].fd;
                pfds[nfds].events = POLLIN;
                if (clients[i].out_len > clients[i].out_off) {
                    pfds[nfds].events |= POLLOUT;
                }
                pfds[nfds].revents = 0;
                nfds++;
            }
        }
        rc = poll(pfds, (nfds_t)nfds, cfg->timeout_ms >= 0 ? cfg->timeout_ms : 250);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            wcat_log_errno("broker_poll", "broker poll failed");
            result = 1;
            break;
        }
        if (rc == 0) {
            continue;
        }
        if ((pfds[0].revents & POLLIN) != 0) {
            char host[128];
            char port[32];
            int fd = wcat_accept(listener, host, sizeof(host), port, sizeof(port));
            if (fd >= 0) {
                if (!wcat_access_check_fd(cfg, fd)) {
                    (void)wcat_close_quiet(fd);
                    continue;
                }
                for (i = 0; i < max_clients && clients[i].fd >= 0; i++) {
                }
                if (i == max_clients) {
                    wcat_log(WCAT_LOG_WARN, "broker_full", "broker client limit reached");
                    (void)wcat_close_quiet(fd);
                } else {
                    (void)wcat_set_nonblock(fd, 1);
                    clients[i].fd = fd;
                    clients[i].id = next_client_id++;
                    clients[i].line_start = true;
                    wcat_log(WCAT_LOG_INFO, "broker_join", "client %s:%s joined", host, port);
                }
            }
        }
        for (i = 0; i < max_clients; i++) {
            ssize_t n;
            int j;
            short revents = 0;

            if (clients[i].fd < 0) {
                continue;
            }
            for (j = 1; j < nfds; j++) {
                if (pfds[j].fd == clients[i].fd) {
                    revents = pfds[j].revents;
                    break;
                }
            }
            if (j == nfds) {
                continue;
            }
            if ((revents & (POLLERR | POLLNVAL)) != 0) {
                drop_client(clients, i);
                continue;
            }
            if ((revents & POLLOUT) != 0 && flush_client(&clients[i]) < 0) {
                drop_client(clients, i);
                continue;
            }
            if ((revents & (POLLIN | POLLHUP)) != 0) {
                do {
                    n = read(clients[i].fd, buf, sizeof(buf));
                } while (n < 0 && errno == EINTR);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    continue;
                }
                if (n <= 0) {
                    drop_client(clients, i);
                    continue;
                }
                if (cfg->hex) {
                    wcat_hexdump("broker", buf, (size_t)n);
                }
                if (cfg->chat) {
                    unsigned char *chat_buf;
                    size_t chat_len = 0;

                    chat_buf = format_chat_message(&clients[i], buf, (size_t)n, &chat_len);
                    if (chat_buf == NULL) {
                        wcat_log(WCAT_LOG_WARN, "broker_drop", "dropping broker client after chat format failure");
                        drop_client(clients, i);
                        continue;
                    }
                    for (j = 0; j < max_clients; j++) {
                        if (clients[j].fd >= 0 && j != i &&
                            queue_bytes(&clients[j], chat_buf, chat_len, max_buffer) < 0) {
                            wcat_log(WCAT_LOG_WARN, "broker_drop", "dropping slow broker client");
                            drop_client(clients, j);
                        }
                    }
                    free(chat_buf);
                    continue;
                }
                for (j = 0; j < max_clients; j++) {
                    if (clients[j].fd >= 0 && j != i &&
                        queue_bytes(&clients[j], buf, (size_t)n, max_buffer) < 0) {
                        wcat_log(WCAT_LOG_WARN, "broker_drop", "dropping slow broker client");
                        drop_client(clients, j);
                    }
                }
            }
        }
    }
    for (i = 0; i < max_clients; i++) {
        if (clients[i].fd >= 0) {
            drop_client(clients, i);
        }
    }
    (void)wcat_close_quiet(listener);
    return result;
}
