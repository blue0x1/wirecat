#include "cli.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "not ok - %s\n", name);
        failures++;
    }
}

static void parse_ok(char **argv, int argc, wcat_mode mode, const char *name)
{
    wcat_config cfg;
    int rc = wcat_parse_args(argc, argv, &cfg);

    check(rc == 0, name);
    check(cfg.mode == mode, name);
}

static void parse_bad(char **argv, int argc, const char *name)
{
    wcat_config cfg;
    int rc = wcat_parse_args(argc, argv, &cfg);

    check(rc < 0, name);
}

int main(void)
{
    char *connect_argv[] = {"wcat", "connect", "--tls", "--ca-file", "ca.pem",
                            "--sni", "service.local", "service.local", "443"};
    char *quic_argv[] = {"wcat", "connect", "--quic", "--alpn", "h3",
                         "service.local", "443"};
    char *listen_argv[] = {"wcat", "listen", "--keep-open", "0.0.0.0", "4444"};
    char *multi_argv[] = {"wcat", "listen", "--multi", "0.0.0.0", "4444"};
    char *relay_argv[] = {"wcat", "relay", "stdio", "exec:/usr/bin/tee"};
    char *broker_argv[] = {"wcat", "broker", "--max-clients", "8",
                           "--broker-buffer", "32768", "127.0.0.1", "5555"};
    char *chat_argv[] = {"wcat", "broker", "--chat", "127.0.0.1", "5555"};
    char *unix_argv[] = {"wcat", "connect", "--unix", "/tmp/wcat.sock"};
    char *sctp_argv[] = {"wcat", "listen", "--sctp", "127.0.0.1", "5555"};
    char *vsock_argv[] = {"wcat", "connect", "--vsock", "2", "5555"};
    char *proxy_server_argv[] = {"wcat", "proxy", "127.0.0.1", "3128"};
    char *acl_argv[] = {"wcat", "listen", "--allow", "127.0.0.1/32,::1/128",
                        "--deny", "192.0.2.1", "127.0.0.1", "4444"};
    char *tls_udp_bad[] = {"wcat", "connect", "--tls", "--udp", "127.0.0.1", "53"};
    char *pty_bad[] = {"wcat", "listen", "--pty", "127.0.0.1", "4444"};
    char *port_bad[] = {"wcat", "connect", "127.0.0.1", "70000"};
    char *clients_bad[] = {"wcat", "broker", "--max-clients", "257",
                           "127.0.0.1", "5555"};
    char *buffer_bad[] = {"wcat", "broker", "--broker-buffer", "12",
                          "127.0.0.1", "5555"};
    char *chat_bad[] = {"wcat", "connect", "--chat", "127.0.0.1", "5555"};
    char *multi_bad[] = {"wcat", "listen", "--multi", "--exec", "/bin/sh",
                         "127.0.0.1", "4444"};
    char *multi_tls_bad[] = {"wcat", "listen", "--multi", "--tls",
                             "127.0.0.1", "4444"};
    char *unix_bad[] = {"wcat", "connect", "--unix", "/tmp/wcat.sock", "1"};
    char *proxy_sctp_bad[] = {"wcat", "connect", "--sctp", "--proxy",
                              "http://127.0.0.1:3128", "127.0.0.1", "5555"};
    char *acl_bad[] = {"wcat", "listen", "--allow", "127.0.0.1/nope",
                       "127.0.0.1", "4444"};
    char *mtls_bad[] = {"wcat", "listen", "--tls", "--require-client-cert",
                        "--cert", "server.pem", "--key", "server.key",
                        "127.0.0.1", "4444"};
    wcat_config cfg;

    parse_ok(connect_argv, 9, WCAT_MODE_CONNECT, "tls connect");
    parse_ok(quic_argv, 7, WCAT_MODE_CONNECT, "quic connect");
    parse_ok(listen_argv, 5, WCAT_MODE_LISTEN, "keep-open listen");
    parse_ok(multi_argv, 5, WCAT_MODE_LISTEN, "multi listen");
    parse_ok(relay_argv, 4, WCAT_MODE_RELAY, "relay");
    parse_ok(broker_argv, 8, WCAT_MODE_BROKER, "broker limits");
    parse_ok(chat_argv, 5, WCAT_MODE_BROKER, "broker chat");
    parse_ok(unix_argv, 4, WCAT_MODE_CONNECT, "unix connect");
    parse_ok(sctp_argv, 5, WCAT_MODE_LISTEN, "sctp listen");
    parse_ok(vsock_argv, 5, WCAT_MODE_CONNECT, "vsock connect");
    parse_ok(proxy_server_argv, 4, WCAT_MODE_PROXY, "proxy server");
    parse_ok(acl_argv, 8, WCAT_MODE_LISTEN, "access lists");

    (void)wcat_parse_args(8, broker_argv, &cfg);
    check(cfg.broker_max_clients == 8, "broker max clients value");
    check(cfg.broker_buffer_bytes == 32768, "broker buffer value");
    check(cfg.family == AF_UNSPEC, "default family");
    check(cfg.tls_verify, "tls verify default");
    (void)wcat_parse_args(5, multi_argv, &cfg);
    check(cfg.multi, "multi listen value");
    (void)wcat_parse_args(5, chat_argv, &cfg);
    check(cfg.chat, "broker chat value");
    (void)wcat_parse_args(4, unix_argv, &cfg);
    check(cfg.unix_socket && strcmp(cfg.host, "/tmp/wcat.sock") == 0, "unix socket value");

    parse_bad(tls_udp_bad, 6, "tls udp reject");
    parse_bad(pty_bad, 5, "pty without exec reject");
    parse_bad(port_bad, 4, "bad port reject");
    parse_bad(clients_bad, 6, "bad max clients reject");
    parse_bad(buffer_bad, 6, "bad broker buffer reject");
    parse_bad(chat_bad, 5, "chat outside broker reject");
    parse_bad(multi_bad, 7, "multi with exec reject");
    parse_bad(multi_tls_bad, 6, "multi with tls reject");
    parse_bad(unix_bad, 5, "unix extra arg reject");
    parse_bad(proxy_sctp_bad, 7, "proxy over sctp reject");
    parse_bad(acl_bad, 6, "bad allow cidr reject");
    parse_bad(mtls_bad, 10, "mtls requires ca reject");

    if (failures == 0) {
        puts("ok - cli parser unit tests");
        return 0;
    }
    return 1;
}
