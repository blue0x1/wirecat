#include "socketx.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/vm_sockets.h>
#endif

int wcat_set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int wcat_set_nonblock(int fd, int enabled)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (enabled) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
}

static int wait_connected(int fd, int timeout_ms)
{
    struct pollfd pfd;
    int err = 0;
    socklen_t len = sizeof(err);
    int rc;

    pfd.fd = fd;
    pfd.events = POLLOUT;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    if (rc <= 0) {
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        return -1;
    }
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 0;
}

static int inet_connect(const char *host, const char *port, int family,
                        int socktype, int protocol, int timeout_ms)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        wcat_log(WCAT_LOG_ERROR, "resolve", "%s:%s: %s", host, port, gai_strerror(rc));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)wcat_set_cloexec(fd);
        if (timeout_ms >= 0) {
            (void)wcat_set_nonblock(fd, 1);
        }
        rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0 || (rc < 0 && errno == EINPROGRESS && timeout_ms >= 0 &&
                        wait_connected(fd, timeout_ms) == 0)) {
            (void)wcat_set_nonblock(fd, 0);
            freeaddrinfo(res);
            return fd;
        }
        (void)wcat_close_quiet(fd);
    }

    freeaddrinfo(res);
    return -1;
}

static int inet_listen(const char *host, const char *port, int family,
                       int socktype, int protocol, int backlog)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int fd = -1;
    int yes = 1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        wcat_log(WCAT_LOG_ERROR, "resolve", "%s:%s: %s", host, port, gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        (void)wcat_set_cloexec(fd);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, backlog) == 0) {
            freeaddrinfo(res);
            return fd;
        }
        (void)wcat_close_quiet(fd);
    }
    freeaddrinfo(res);
    return -1;
}

int wcat_tcp_connect(const char *host, const char *port, int family, int timeout_ms)
{
    return inet_connect(host, port, family, SOCK_STREAM, IPPROTO_TCP, timeout_ms);
}

int wcat_tcp_listen(const char *host, const char *port, int family, int backlog)
{
    return inet_listen(host, port, family, SOCK_STREAM, IPPROTO_TCP, backlog);
}

int wcat_sctp_connect(const char *host, const char *port, int family, int timeout_ms)
{
    return inet_connect(host, port, family, SOCK_STREAM, IPPROTO_SCTP, timeout_ms);
}

int wcat_sctp_listen(const char *host, const char *port, int family, int backlog)
{
    return inet_listen(host, port, family, SOCK_STREAM, IPPROTO_SCTP, backlog);
}

int wcat_unix_connect(const char *path, int timeout_ms)
{
    struct sockaddr_un addr;
    int fd;
    int rc;

    if (path == NULL || strlen(path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)wcat_set_cloexec(fd);
    if (timeout_ms >= 0) {
        (void)wcat_set_nonblock(fd, 1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0 || (rc < 0 && errno == EINPROGRESS && timeout_ms >= 0 &&
                    wait_connected(fd, timeout_ms) == 0)) {
        (void)wcat_set_nonblock(fd, 0);
        return fd;
    }
    return wcat_close_quiet(fd);
}

int wcat_unix_listen(const char *path, int backlog)
{
    struct sockaddr_un addr;
    int fd;

    if (path == NULL || strlen(path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)wcat_set_cloexec(fd);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    (void)unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, backlog) == 0) {
        return fd;
    }
    return wcat_close_quiet(fd);
}

static int parse_u32_arg(const char *s, unsigned int *out)
{
    char *end = NULL;
    unsigned long value;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    value = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || value > 0xffffffffUL) {
        return -1;
    }
    *out = (unsigned int)value;
    return 0;
}

int wcat_vsock_connect(const char *cid, const char *port, int timeout_ms)
{
#ifdef __linux__
    struct sockaddr_vm addr;
    unsigned int cid_value;
    unsigned int port_value;
    int fd;
    int rc;

    if (parse_u32_arg(cid, &cid_value) < 0 || parse_u32_arg(port, &port_value) < 0) {
        errno = EINVAL;
        return -1;
    }
    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)wcat_set_cloexec(fd);
    if (timeout_ms >= 0) {
        (void)wcat_set_nonblock(fd, 1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = cid_value;
    addr.svm_port = port_value;
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0 || (rc < 0 && errno == EINPROGRESS && timeout_ms >= 0 &&
                    wait_connected(fd, timeout_ms) == 0)) {
        (void)wcat_set_nonblock(fd, 0);
        return fd;
    }
    return wcat_close_quiet(fd);
#else
    (void)cid;
    (void)port;
    (void)timeout_ms;
    errno = EAFNOSUPPORT;
    return -1;
#endif
}

int wcat_vsock_listen(const char *cid, const char *port, int backlog)
{
#ifdef __linux__
    struct sockaddr_vm addr;
    unsigned int cid_value;
    unsigned int port_value;
    int fd;

    if (cid == NULL || strcmp(cid, "-") == 0 || strcmp(cid, "*") == 0 ||
        strcmp(cid, "any") == 0) {
        cid_value = VMADDR_CID_ANY;
    } else if (parse_u32_arg(cid, &cid_value) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (parse_u32_arg(port, &port_value) < 0) {
        errno = EINVAL;
        return -1;
    }
    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)wcat_set_cloexec(fd);
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = cid_value;
    addr.svm_port = port_value;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, backlog) == 0) {
        return fd;
    }
    return wcat_close_quiet(fd);
#else
    (void)cid;
    (void)port;
    (void)backlog;
    errno = EAFNOSUPPORT;
    return -1;
#endif
}

int wcat_udp_connect(const char *host, const char *port, int family)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        wcat_log(WCAT_LOG_ERROR, "resolve", "%s:%s: %s", host, port, gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)wcat_set_cloexec(fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return fd;
        }
        (void)wcat_close_quiet(fd);
    }
    freeaddrinfo(res);
    return -1;
}

int wcat_udp_bind(const char *host, const char *port, int family)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        wcat_log(WCAT_LOG_ERROR, "resolve", "%s:%s: %s", host, port, gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)wcat_set_cloexec(fd);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return fd;
        }
        (void)wcat_close_quiet(fd);
    }
    freeaddrinfo(res);
    return -1;
}

int wcat_accept(int listener, char *host, size_t host_len, char *port, size_t port_len)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    int fd;

    do {
        fd = accept(listener, (struct sockaddr *)&ss, &len);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return -1;
    }
    (void)wcat_set_cloexec(fd);
    if (host != NULL && port != NULL) {
        (void)getnameinfo((struct sockaddr *)&ss, len, host, (socklen_t)host_len,
                          port, (socklen_t)port_len,
                          NI_NUMERICHOST | NI_NUMERICSERV);
    }
    return fd;
}
