#ifndef WCAT_SOCKETX_H
#define WCAT_SOCKETX_H

#include <sys/socket.h>

int wcat_tcp_connect(const char *host, const char *port, int family, int timeout_ms);
int wcat_tcp_listen(const char *host, const char *port, int family, int backlog);
int wcat_sctp_connect(const char *host, const char *port, int family, int timeout_ms);
int wcat_sctp_listen(const char *host, const char *port, int family, int backlog);
int wcat_udp_connect(const char *host, const char *port, int family);
int wcat_udp_bind(const char *host, const char *port, int family);
int wcat_unix_connect(const char *path, int timeout_ms);
int wcat_unix_listen(const char *path, int backlog);
int wcat_vsock_connect(const char *cid, const char *port, int timeout_ms);
int wcat_vsock_listen(const char *cid, const char *port, int backlog);
int wcat_accept(int listener, char *host, size_t host_len, char *port, size_t port_len);
int wcat_set_nonblock(int fd, int enabled);
int wcat_set_cloexec(int fd);

#endif
