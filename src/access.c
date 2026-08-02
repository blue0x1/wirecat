#include "access.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef struct {
    int family;
    unsigned char addr[16];
    int bits;
} access_net;

static int parse_net(const char *spec, access_net *net)
{
    char ip[INET6_ADDRSTRLEN];
    const char *slash;
    char *end = NULL;
    long bits;
    size_t len;

    if (spec == NULL || *spec == '\0') {
        return -1;
    }
    slash = strchr(spec, '/');
    len = slash != NULL ? (size_t)(slash - spec) : strlen(spec);
    if (len == 0 || len >= sizeof(ip)) {
        return -1;
    }
    memcpy(ip, spec, len);
    ip[len] = '\0';

    if (inet_pton(AF_INET, ip, net->addr) == 1) {
        net->family = AF_INET;
        if (slash == NULL) {
            net->bits = 32;
            return 0;
        }
        bits = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || bits < 0 || bits > 32) {
            return -1;
        }
        net->bits = (int)bits;
        return 0;
    }
    if (inet_pton(AF_INET6, ip, net->addr) == 1) {
        net->family = AF_INET6;
        if (slash == NULL) {
            net->bits = 128;
            return 0;
        }
        bits = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || bits < 0 || bits > 128) {
            return -1;
        }
        net->bits = (int)bits;
        return 0;
    }
    return -1;
}

static int match_net(const unsigned char *addr, const access_net *net)
{
    int full = net->bits / 8;
    int rem = net->bits % 8;

    if (full > 0 && memcmp(addr, net->addr, (size_t)full) != 0) {
        return 0;
    }
    if (rem != 0) {
        unsigned char mask = (unsigned char)(0xffu << (8 - rem));
        if ((addr[full] & mask) != (net->addr[full] & mask)) {
            return 0;
        }
    }
    return 1;
}

static int fd_peer_addr(int fd, int *family, unsigned char *addr, char *text, size_t text_len)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);

    if (getpeername(fd, (struct sockaddr *)&ss, &len) < 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&ss;
        *family = AF_INET;
        memcpy(addr, &sin->sin_addr, 4);
        (void)inet_ntop(AF_INET, &sin->sin_addr, text, (socklen_t)text_len);
        return 0;
    }
    if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&ss;
        *family = AF_INET6;
        memcpy(addr, &sin6->sin6_addr, 16);
        (void)inet_ntop(AF_INET6, &sin6->sin6_addr, text, (socklen_t)text_len);
        return 0;
    }
    return -1;
}

static int list_matches(const char *list, int family, const unsigned char *addr)
{
    char token[INET6_ADDRSTRLEN + 8];
    const char *p = list;

    while (p != NULL && *p != '\0') {
        access_net net;
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);

        while (len > 0 && (*p == ' ' || *p == '\t')) {
            p++;
            len--;
        }
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
            len--;
        }
        if (len > 0 && len < sizeof(token)) {
            memcpy(token, p, len);
            token[len] = '\0';
            if (parse_net(token, &net) == 0 && net.family == family && match_net(addr, &net)) {
                return 1;
            }
        }
        p = comma != NULL ? comma + 1 : NULL;
    }
    return 0;
}

int wcat_access_validate_list(const char *list)
{
    char token[INET6_ADDRSTRLEN + 8];
    const char *p = list;

    if (list == NULL) {
        return 0;
    }
    while (p != NULL && *p != '\0') {
        access_net net;
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);

        while (len > 0 && (*p == ' ' || *p == '\t')) {
            p++;
            len--;
        }
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
            len--;
        }
        if (len == 0 || len >= sizeof(token)) {
            return -1;
        }
        memcpy(token, p, len);
        token[len] = '\0';
        if (parse_net(token, &net) < 0) {
            return -1;
        }
        p = comma != NULL ? comma + 1 : NULL;
    }
    return 0;
}

int wcat_access_check_fd(const wcat_config *cfg, int fd)
{
    unsigned char addr[16];
    char text[INET6_ADDRSTRLEN] = "";
    int family;

    if (cfg->allow_list == NULL && cfg->deny_list == NULL) {
        return 1;
    }
    if (fd_peer_addr(fd, &family, addr, text, sizeof(text)) < 0) {
        wcat_log_errno("access", "failed to read peer address");
        return 0;
    }
    if (cfg->deny_list != NULL && list_matches(cfg->deny_list, family, addr)) {
        wcat_log(WCAT_LOG_WARN, "access_denied", "denied peer %s", text);
        return 0;
    }
    if (cfg->allow_list != NULL && !list_matches(cfg->allow_list, family, addr)) {
        wcat_log(WCAT_LOG_WARN, "access_denied", "peer %s not in allow list", text);
        return 0;
    }
    return 1;
}
