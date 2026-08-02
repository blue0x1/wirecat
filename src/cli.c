#include "access.h"
#include "cli.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define WCAT_DEFAULT_BROKER_MAX_CLIENTS 64
#define WCAT_DEFAULT_BROKER_BUFFER_BYTES 65536

void wcat_config_init(wcat_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->family = AF_UNSPEC;
    cfg->timeout_ms = -1;
    cfg->tls_verify = true;
    cfg->alpn = "wcat/1";
    cfg->broker_max_clients = WCAT_DEFAULT_BROKER_MAX_CLIENTS;
    cfg->broker_buffer_bytes = WCAT_DEFAULT_BROKER_BUFFER_BYTES;
}

static int parse_range_int(const char *s, int min, int max)
{
    char *end = NULL;
    long value;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    value = strtol(s, &end, 10);
    if (end == s || *end != '\0' || value < min || value > max) {
        return -1;
    }
    return (int)value;
}

static int parse_common(int argc, char **argv, int *idx, wcat_config *cfg)
{
    const char *arg = argv[*idx];

    if (strcmp(arg, "-u") == 0 || strcmp(arg, "--udp") == 0) {
        cfg->udp = true;
    } else if (strcmp(arg, "-4") == 0) {
        cfg->family = AF_INET;
    } else if (strcmp(arg, "-6") == 0) {
        cfg->family = AF_INET6;
    } else if (strcmp(arg, "-k") == 0 || strcmp(arg, "--keep-open") == 0) {
        cfg->keep_open = true;
    } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
        cfg->verbose = true;
    } else if (strcmp(arg, "--json") == 0) {
        cfg->json = true;
    } else if (strcmp(arg, "--hex") == 0) {
        cfg->hex = true;
    } else if (strcmp(arg, "--chat") == 0) {
        cfg->chat = true;
    } else if (strcmp(arg, "-U") == 0 || strcmp(arg, "--unix") == 0) {
        cfg->unix_socket = true;
    } else if (strcmp(arg, "--sctp") == 0) {
        cfg->sctp = true;
    } else if (strcmp(arg, "--vsock") == 0) {
        cfg->vsock = true;
    } else if (strcmp(arg, "--tls") == 0) {
        cfg->tls = true;
    } else if (strcmp(arg, "--quic") == 0) {
        cfg->quic = true;
        cfg->tls = true;
    } else if (strcmp(arg, "--tls-insecure") == 0) {
        cfg->tls = true;
        cfg->tls_verify = false;
    } else if (strcmp(arg, "--tls-verify") == 0) {
        cfg->tls = true;
        cfg->tls_verify = true;
    } else if (strcmp(arg, "--pty") == 0) {
        cfg->pty = true;
    } else if (strcmp(arg, "--timeout") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->timeout_ms = wcat_parse_timeout_ms(argv[*idx]);
        if (cfg->timeout_ms < 0) {
            return -1;
        }
    } else if (strcmp(arg, "--cert") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->cert_file = argv[*idx];
    } else if (strcmp(arg, "--key") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->key_file = argv[*idx];
    } else if (strcmp(arg, "--client-cert") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->client_cert_file = argv[*idx];
        cfg->tls = true;
    } else if (strcmp(arg, "--client-key") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->client_key_file = argv[*idx];
        cfg->tls = true;
    } else if (strcmp(arg, "--require-client-cert") == 0) {
        cfg->tls = true;
        cfg->tls_require_client_cert = true;
    } else if (strcmp(arg, "--ca-file") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->ca_file = argv[*idx];
    } else if (strcmp(arg, "--sni") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->sni = argv[*idx];
    } else if (strcmp(arg, "--alpn") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        if (strlen(argv[*idx]) == 0 || strlen(argv[*idx]) > 255) {
            return -1;
        }
        cfg->alpn = argv[*idx];
    } else if (strcmp(arg, "--proxy") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->proxy_url = argv[*idx];
    } else if (strcmp(arg, "--exec") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->exec_path = argv[*idx];
    } else if (strcmp(arg, "--max-clients") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->broker_max_clients = parse_range_int(argv[*idx], 1, 256);
        if (cfg->broker_max_clients < 0) {
            return -1;
        }
    } else if (strcmp(arg, "--broker-buffer") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->broker_buffer_bytes = parse_range_int(argv[*idx], 1024, 1048576);
        if (cfg->broker_buffer_bytes < 0) {
            return -1;
        }
    } else if (strcmp(arg, "--allow") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->allow_list = argv[*idx];
    } else if (strcmp(arg, "--deny") == 0) {
        if (++(*idx) >= argc) {
            return -1;
        }
        cfg->deny_list = argv[*idx];
    } else {
        return 1;
    }
    return 0;
}

static int parse_options(int argc, char **argv, int *idx, wcat_config *cfg)
{
    int rc;

    while (*idx < argc) {
        if (argv[*idx][0] != '-' || strcmp(argv[*idx], "-") == 0) {
            break;
        }
        if (strcmp(argv[*idx], "--") == 0) {
            (*idx)++;
            break;
        }
        rc = parse_common(argc, argv, idx, cfg);
        if (rc != 0) {
            return -1;
        }
        (*idx)++;
    }
    return 0;
}

int wcat_parse_args(int argc, char **argv, wcat_config *cfg)
{
    int i = 2;

    wcat_config_init(cfg);
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        return 1;
    }

    if (strcmp(argv[1], "connect") == 0) {
        cfg->mode = WCAT_MODE_CONNECT;
    } else if (strcmp(argv[1], "listen") == 0) {
        cfg->mode = WCAT_MODE_LISTEN;
    } else if (strcmp(argv[1], "send") == 0) {
        cfg->mode = WCAT_MODE_SEND;
    } else if (strcmp(argv[1], "recv") == 0) {
        cfg->mode = WCAT_MODE_RECV;
    } else if (strcmp(argv[1], "relay") == 0) {
        cfg->mode = WCAT_MODE_RELAY;
    } else if (strcmp(argv[1], "broker") == 0) {
        cfg->mode = WCAT_MODE_BROKER;
    } else if (strcmp(argv[1], "proxy") == 0) {
        cfg->mode = WCAT_MODE_PROXY;
    } else {
        return -1;
    }

    if (parse_options(argc, argv, &i, cfg) < 0) {
        return -1;
    }

    if (cfg->mode == WCAT_MODE_SEND || cfg->mode == WCAT_MODE_RECV) {
        if (argc - i != 3) {
            return -1;
        }
        cfg->file = argv[i];
        cfg->host = argv[i + 1];
        cfg->port = argv[i + 2];
    } else if (cfg->mode == WCAT_MODE_RELAY) {
        if (argc - i != 2) {
            return -1;
        }
        cfg->left = argv[i];
        cfg->right = argv[i + 1];
    } else if (cfg->unix_socket &&
               (cfg->mode == WCAT_MODE_CONNECT || cfg->mode == WCAT_MODE_LISTEN ||
                cfg->mode == WCAT_MODE_BROKER)) {
        if (argc - i != 1) {
            return -1;
        }
        cfg->host = argv[i];
        cfg->port = "0";
    } else {
        if (argc - i != 2) {
            return -1;
        }
        cfg->host = argv[i];
        cfg->port = argv[i + 1];
    }

    if (!cfg->unix_socket && cfg->port != NULL && wcat_parse_port(cfg->port) < 0) {
        return -1;
    }
    if (cfg->tls && cfg->udp) {
        return -1;
    }
    if ((cfg->udp ? 1 : 0) + (cfg->sctp ? 1 : 0) + (cfg->unix_socket ? 1 : 0) +
        (cfg->vsock ? 1 : 0) > 1) {
        return -1;
    }
    if (cfg->quic && cfg->proxy_url != NULL) {
        return -1;
    }
    if (cfg->quic && cfg->mode != WCAT_MODE_CONNECT && cfg->mode != WCAT_MODE_LISTEN) {
        return -1;
    }
    if ((cfg->sctp || cfg->unix_socket || cfg->vsock) &&
        cfg->mode != WCAT_MODE_CONNECT && cfg->mode != WCAT_MODE_LISTEN &&
        cfg->mode != WCAT_MODE_BROKER && cfg->mode != WCAT_MODE_RELAY) {
        return -1;
    }
    if ((cfg->sctp || cfg->unix_socket || cfg->vsock) && cfg->proxy_url != NULL) {
        return -1;
    }
    if (cfg->pty && cfg->exec_path == NULL) {
        return -1;
    }
    if (cfg->chat && cfg->mode != WCAT_MODE_BROKER) {
        return -1;
    }
    if ((cfg->client_cert_file == NULL) != (cfg->client_key_file == NULL)) {
        return -1;
    }
    if (cfg->tls_require_client_cert && cfg->ca_file == NULL) {
        return -1;
    }
    if (wcat_access_validate_list(cfg->allow_list) < 0 ||
        wcat_access_validate_list(cfg->deny_list) < 0) {
        return -1;
    }
    return 0;
}

void wcat_print_help(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s connect [options] HOST PORT\n", argv0);
    printf("  %s listen  [options] HOST PORT\n", argv0);
    printf("  %s send    [options] FILE HOST PORT\n", argv0);
    printf("  %s recv    [options] FILE HOST PORT\n", argv0);
    printf("  %s relay   [options] LEFT RIGHT\n", argv0);
    printf("  %s broker  [options] HOST PORT\n", argv0);
    printf("  %s proxy   [options] HOST PORT\n\n", argv0);
    printf("Options:\n");
    printf("      --version         print version information\n");
    printf("  -u, --udp             use UDP\n");
    printf("  -4                    force IPv4\n");
    printf("  -6                    force IPv6\n");
    printf("  -k, --keep-open       accept sequential clients\n");
    printf("  -v, --verbose         verbose logs\n");
    printf("      --json            JSON logs\n");
    printf("      --hex             hex dump traffic\n");
    printf("      --chat            broker chat labels and control-byte escaping\n");
    printf("  -U, --unix            use Unix domain sockets; HOST is socket path\n");
    printf("      --sctp            use SCTP stream sockets\n");
    printf("      --vsock           use Linux AF_VSOCK; HOST is CID or 'any' for listen\n");
    printf("      --timeout SEC     timeout in seconds\n");
    printf("      --tls             enable TLS\n");
    printf("      --quic            use QUIC single-stream transport\n");
    printf("      --tls-verify      verify TLS peer certificate (client default)\n");
    printf("      --tls-insecure    disable TLS peer verification\n");
    printf("      --ca-file FILE    TLS CA bundle for verification\n");
    printf("      --sni NAME        TLS SNI and hostname verification name\n");
    printf("      --alpn NAME       TLS/QUIC ALPN value (default wcat/1)\n");
    printf("      --cert FILE       TLS server certificate\n");
    printf("      --key FILE        TLS server key\n");
    printf("      --client-cert FILE TLS client certificate\n");
    printf("      --client-key FILE TLS client private key\n");
    printf("      --require-client-cert require verified TLS client certificate\n");
    printf("      --proxy URL       socks5://host:port or http://host:port\n");
    printf("      --exec PATH       bridge connection to process\n");
    printf("      --pty             use POSIX PTY for --exec\n");
    printf("      --max-clients N   broker client limit, 1-256 (default 64)\n");
    printf("      --broker-buffer N broker per-client output buffer bytes\n");
    printf("      --allow LIST      accept only IP/CIDR peers in comma list\n");
    printf("      --deny LIST       reject IP/CIDR peers in comma list\n");
    printf("\nRelay endpoints:\n");
    printf("  - | stdio             standard input/output\n");
    printf("  tcp:HOST:PORT         outbound TCP connection\n");
    printf("  listen:HOST:PORT      inbound TCP listener, accepts one peer\n");
    printf("  unix:PATH             outbound Unix domain socket connection\n");
    printf("  unix-listen:PATH      inbound Unix domain socket listener\n");
    printf("  file:PATH             read/write file endpoint\n");
    printf("  exec:PATH             process endpoint using pipes\n");
    printf("  pty:PATH              process endpoint using a POSIX PTY\n");
    printf("\nExamples:\n");
    printf("  %s connect example.com 80\n", argv0);
    printf("  %s listen --keep-open 0.0.0.0 4444\n", argv0);
    printf("  %s connect --tls example.com 443\n", argv0);
    printf("  %s connect --quic --alpn h3 example.com 443\n", argv0);
    printf("  %s connect --tls-insecure 127.0.0.1 8443\n", argv0);
    printf("  %s listen --tls --cert server.crt --key server.key 0.0.0.0 8443\n", argv0);
    printf("  %s listen --allow 127.0.0.1/32 127.0.0.1 4444\n", argv0);
    printf("  %s connect --proxy socks5://127.0.0.1:9050 example.com 80\n", argv0);
    printf("  %s connect --proxy http://127.0.0.1:8080 example.com 443\n", argv0);
    printf("  %s listen --pty --exec /bin/sh 127.0.0.1 4444\n", argv0);
    printf("  %s send ./archive.tar 192.0.2.10 9000\n", argv0);
    printf("  %s recv ./archive.tar 0.0.0.0 9000\n", argv0);
    printf("  %s relay - exec:/usr/bin/tee\n", argv0);
    printf("  %s relay listen:127.0.0.1:9000 tcp:10.0.0.5:22\n", argv0);
    printf("  %s relay listen:0.0.0.0:4444 pty:/bin/sh\n", argv0);
    printf("  %s broker --json 0.0.0.0 5555\n", argv0);
    printf("  %s broker --unix --chat /tmp/wcat-chat.sock\n", argv0);
    printf("  %s broker --chat --max-clients 16 --broker-buffer 131072 0.0.0.0 5555\n", argv0);
    printf("  %s proxy 127.0.0.1 3128\n", argv0);
    printf("  %s connect --json --hex example.com 80\n", argv0);
}
