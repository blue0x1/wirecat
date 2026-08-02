# WCAT(1)

## NAME

wcat - modern native stream and session utility

## SYNOPSIS

`wcat connect [OPTIONS] HOST PORT`

`wcat listen [OPTIONS] HOST PORT`

`wcat send [OPTIONS] FILE HOST PORT`

`wcat recv [OPTIONS] FILE HOST PORT`

`wcat relay [OPTIONS] LEFT RIGHT`

`wcat broker [OPTIONS] HOST PORT`

`wcat proxy [OPTIONS] HOST PORT`

`wcat --version`

## DESCRIPTION

`wcat` connects, listens, relays, proxies, transfers files, and bridges
processes or PTYs to network streams.

Version 0.1.0 is authored by Chokri Hammedi (`blue0x1`).

## OPTIONS

`--version`
: Print version and author information.

`-u`, `--udp`
: Use UDP.

`-4`
: Force IPv4.

`-6`
: Force IPv6.

`-k`, `--keep-open`
: Keep a listener open for sequential clients.

`-v`, `--verbose`
: Enable verbose logging.

`--json`
: Emit JSON log records.

`--hex`
: Print traffic hex dumps.

`--chat`
: In broker mode, prefix relayed messages with a client label and escape
  terminal control bytes.

`-U`, `--unix`
: Use Unix domain sockets. For `connect`, `listen`, and `broker`, `HOST` is
  the socket path and `PORT` is omitted.

`--sctp`
: Use SCTP stream sockets instead of TCP. Runtime support depends on the host
  kernel.

`--vsock`
: Use Linux AF_VSOCK stream sockets. In listen mode, `HOST` may be `any`.

`--timeout SEC`
: Set connect and relay timeout in seconds.

`--tls`
: Enable TLS.

`--quic`
: Use QUIC single-stream transport for `connect` or `listen`.

`--tls-verify`
: Verify TLS peer certificates in client mode. This is the default.

`--tls-insecure`
: Disable TLS peer verification.

`--ca-file FILE`
: Use a CA bundle for TLS peer verification.

`--sni NAME`
: Set TLS SNI and hostname verification name.

`--alpn NAME`
: Set TLS/QUIC ALPN. The default is `wcat/1`.

`--cert FILE`
: TLS server certificate.

`--key FILE`
: TLS server private key.

`--client-cert FILE`
: TLS client certificate.

`--client-key FILE`
: TLS client private key.

`--require-client-cert`
: Require a verified TLS client certificate in server mode. `--ca-file` must
  identify the CA bundle used to verify clients.

`--proxy URL`
: Use an outbound proxy. Supported forms are `socks5://host:port` and
  `http://host:port`.

`--exec PATH`
: Bridge the peer to a local process.

`--pty`
: Allocate a PTY for `--exec`.

Interactive shell sessions should use `--pty --exec PATH`, including QUIC
sessions.

`--max-clients N`
: Set the broker client limit, from `1` to `256`. The default is `64`.

`--broker-buffer N`
: Set the broker per-client output buffer in bytes. Slow clients are dropped
  when their queued output exceeds this limit.

`--allow LIST`
: Accept only TCP peers matching the comma-separated IP/CIDR list.

`--deny LIST`
: Reject TCP peers matching the comma-separated IP/CIDR list. Deny rules are
  evaluated before allow rules.

## RELAY ENDPOINTS

`wcat relay [OPTIONS] LEFT RIGHT` connects two endpoints and moves bytes in both
directions.

Supported endpoint forms:

`-`
: Standard input/output.

`stdio`
: Standard input/output.

`tcp:HOST:PORT`
: Open an outbound TCP connection.

`listen:HOST:PORT`
: Open an inbound TCP listener and accept one peer.

`unix:PATH`
: Open an outbound Unix domain socket connection.

`unix-listen:PATH`
: Open an inbound Unix domain socket listener and accept one peer.

`file:PATH`
: Open a read/write file endpoint, creating the file with mode `0600` if needed.

`exec:PATH`
: Start a process and bridge it with pipes.

`pty:PATH`
: Start a process and bridge it with a POSIX PTY.

Examples:

```sh
wcat relay - tcp:example.com:80
wcat relay listen:127.0.0.1:9000 tcp:10.0.0.5:22
wcat relay unix-listen:/tmp/wcat.sock exec:/usr/bin/tee
wcat relay - exec:/usr/bin/tee
wcat relay tcp:127.0.0.1:9000 file:./capture.bin
wcat relay listen:0.0.0.0:4444 pty:/bin/sh
wcat proxy 127.0.0.1 3128
```

## EXIT STATUS

`0`
: Success.

`1`
: Runtime or network failure.

`2`
: Invalid command-line usage.
