#ifndef WCAT_PROXY_H
#define WCAT_PROXY_H

#include "cli.h"

typedef enum {
    WCAT_PROXY_NONE = 0,
    WCAT_PROXY_SOCKS5,
    WCAT_PROXY_HTTP
} wcat_proxy_type;

typedef struct {
    wcat_proxy_type type;
    char host[256];
    char port[16];
} wcat_proxy;

int wcat_proxy_parse(const char *url, wcat_proxy *proxy);
int wcat_proxy_connect(const wcat_proxy *proxy, const char *dst_host,
                       const char *dst_port, int family, int timeout_ms);
int wcat_proxy_server_run(const wcat_config *cfg);

#endif
