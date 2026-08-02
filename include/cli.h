#ifndef WCAT_CLI_H
#define WCAT_CLI_H

#include <stdbool.h>

typedef enum {
    WCAT_MODE_NONE = 0,
    WCAT_MODE_CONNECT,
    WCAT_MODE_LISTEN,
    WCAT_MODE_SEND,
    WCAT_MODE_RECV,
    WCAT_MODE_RELAY,
    WCAT_MODE_BROKER,
    WCAT_MODE_PROXY
} wcat_mode;

typedef struct {
    wcat_mode mode;
    const char *host;
    const char *port;
    const char *file;
    const char *left;
    const char *right;
    const char *exec_path;
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *sni;
    const char *proxy_url;
    const char *alpn;
    const char *client_cert_file;
    const char *client_key_file;
    const char *allow_list;
    const char *deny_list;
    bool udp;
    bool tls;
    bool tls_verify;
    bool keep_open;
    bool verbose;
    bool json;
    bool hex;
    bool pty;
    bool chat;
    bool unix_socket;
    bool sctp;
    bool vsock;
    bool tls_require_client_cert;
    bool quic;
    int family;
    int timeout_ms;
    int broker_max_clients;
    int broker_buffer_bytes;
} wcat_config;

void wcat_config_init(wcat_config *cfg);
int wcat_parse_args(int argc, char **argv, wcat_config *cfg);
void wcat_print_help(const char *argv0);

#endif
