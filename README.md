# Wirecat

Wirecat (`wcat`) is a modern native stream and session utility for networking,
debugging, secure relays, shell handling, and file movement. It is designed for
short commands, predictable behavior, strong interactive handling, and
automation-friendly output.

Current release: `0.1.0`

Author: Chokri Hammedi (`blue0x1`)

This repository is a production-oriented implementation in C. The code is
intentionally modular, POSIX-first, dependency-conscious, and structured for
Debian/Kali packaging.

## Goals

- One native CLI binary with predictable behavior.
- Clean TCP, UDP, SCTP, Unix domain socket, and Linux VSOCK client/listener
  modes.
- IPv4 and IPv6 via `getaddrinfo(3)`.
- TLS client and server support through OpenSSL, with client verification
  enabled by default.
- SOCKS5 and HTTP CONNECT proxy support for outbound TCP connections.
- HTTP CONNECT proxy server mode.
- Bidirectional relay primitives for sockets, files, processes, and PTYs.
- Stable PTY-backed shell sessions on Linux.
- Keep-open listeners for sequential clients.
- Basic chat/broker mode with optional client labels and control-byte escaping.
- Human-readable logs by default, JSON logs for automation.
- Clear exit codes, signal handling, and timeout controls.

## Build

```sh
make
```

Useful variants:

```sh
make CC=clang
make debug
make test
make asan
make analyze
make fuzz-harness
make clean
```

Dependencies:

- POSIX libc and toolchain
- OpenSSL development headers and libraries

On Debian/Kali:

```sh
sudo apt install build-essential pkg-config libssl-dev
```

## Quick Examples

TCP client:

```sh
wcat connect example.com 80
```

Version:

```sh
wcat --version
```

TCP listener:

```sh
wcat listen 0.0.0.0 4444
```

Keep-open listener:

```sh
wcat listen --keep-open 0.0.0.0 4444
```

TLS client:

```sh
wcat connect --tls example.com 443
```

QUIC client:

```sh
wcat connect --quic --alpn h3 example.com 443
```

TLS client with a private CA bundle:

```sh
wcat connect --tls --ca-file ./ca.pem --sni service.example service.example 443
```

TLS client with a certificate:

```sh
wcat connect --tls --ca-file ./ca.pem --sni service.example --client-cert client.crt --client-key client.key service.example 443
```

TLS server:

```sh
wcat listen --tls --cert server.crt --key server.key 0.0.0.0 8443
```

TLS server requiring client certificates:

```sh
wcat listen --tls --require-client-cert --ca-file ./clients-ca.pem --cert server.crt --key server.key 0.0.0.0 8443
```

QUIC listener for another `wcat` peer:

```sh
wcat listen --quic --cert server.crt --key server.key 0.0.0.0 8443
```

QUIC PTY-backed shell listener:

```sh
wcat listen --quic --tls-insecure --cert server.crt --key server.key --pty --exec /bin/bash 127.0.0.1 8443
```

Listener restricted to a peer range:

```sh
wcat listen --allow 192.0.2.0/24 0.0.0.0 4444
```

SOCKS5 proxy:

```sh
wcat connect --proxy socks5://127.0.0.1:9050 example.com 80
```

HTTP CONNECT proxy:

```sh
wcat connect --proxy http://proxy.local:8080 example.com 443
```

HTTP CONNECT proxy server:

```sh
wcat proxy 127.0.0.1 3128
```

Unix domain socket:

```sh
wcat listen --unix --exec /usr/bin/tee /tmp/wcat.sock
wcat connect --unix /tmp/wcat.sock
```

SCTP stream socket:

```sh
wcat listen --sctp 0.0.0.0 5555
wcat connect --sctp 127.0.0.1 5555
```

Linux VSOCK stream socket:

```sh
wcat listen --vsock any 5555
wcat connect --vsock 2 5555
```

PTY-backed shell listener:

```sh
wcat listen --pty --exec /bin/bash 0.0.0.0 4444
```

File send:

```sh
wcat send ./archive.tar 192.0.2.10 9000
```

File receive:

```sh
wcat recv ./archive.tar 0.0.0.0 9000
```

Chat broker:

```sh
wcat broker 0.0.0.0 5555
```

Chat broker with client labels and control-byte escaping:

```sh
wcat broker --chat 0.0.0.0 5555
```

Broker with explicit limits:

```sh
wcat broker --chat --max-clients 16 --broker-buffer 131072 0.0.0.0 5555
```

JSON logging and hex dump:

```sh
wcat connect --json --hex example.com 80
```

## CLI Shape

Wirecat uses subcommands for the major workflows:

```text
wcat connect [options] HOST PORT
wcat listen  [options] HOST PORT
wcat send    [options] FILE HOST PORT
wcat recv    [options] FILE HOST PORT
wcat relay   [options] LEFT RIGHT
wcat broker  [options] HOST PORT
wcat proxy   [options] HOST PORT
```

Common options:

```text
-u, --udp                  use UDP
-4                         force IPv4
-6                         force IPv6
-k, --keep-open            accept sequential clients
-v, --verbose              verbose logging
--json                     structured JSON logs
--hex                      hex dump traffic
--chat                     broker chat labels and control-byte escaping
-U, --unix                 use Unix domain sockets; HOST is socket path
--sctp                     use SCTP stream sockets
--vsock                    use Linux AF_VSOCK; HOST is CID or any for listen
--timeout SEC              connection and idle timeout
--tls                      enable TLS
--quic                     use QUIC single-stream transport
--tls-verify               verify TLS peer certificate (client default)
--tls-insecure             disable TLS peer verification
--ca-file FILE             TLS CA bundle for verification
--sni NAME                 TLS SNI and hostname verification name
--alpn NAME                TLS/QUIC ALPN value (default wcat/1)
--cert FILE                TLS server certificate
--key FILE                 TLS server private key
--client-cert FILE         TLS client certificate
--client-key FILE          TLS client private key
--require-client-cert      require verified TLS client certificate
--proxy URL                socks5://host:port or http://host:port
--exec PATH                bridge peer to process
--pty                      allocate PTY for --exec
--max-clients N            broker client limit, 1-256 (default 64)
--broker-buffer N          broker per-client output buffer bytes
--allow LIST               accept only IP/CIDR peers in comma list
--deny LIST                reject IP/CIDR peers in comma list
```

## Relay Endpoint Grammar

Relay mode connects two endpoints and moves bytes in both directions:

```text
wcat relay [options] LEFT RIGHT
```

Supported endpoint forms:

```text
-                    standard input/output
stdio                standard input/output
tcp:HOST:PORT        outbound TCP connection
listen:HOST:PORT     inbound TCP listener, accepts one peer
unix:PATH            outbound Unix domain socket connection
unix-listen:PATH     inbound Unix domain socket listener, accepts one peer
file:PATH            read/write file endpoint, created if missing
exec:PATH            process endpoint using pipes
pty:PATH             process endpoint using a POSIX PTY
```

Current rules:

- `HOST` may be an IPv4 address, IPv6 address, or resolvable hostname.
- `PORT` must be numeric, from `1` to `65535`.
- `listen:HOST:PORT` accepts one connection for the relay session.
- `unix:PATH` and `unix-listen:PATH` use stream Unix domain sockets.
- `exec:PATH` and `pty:PATH` execute the path directly; shell parsing is not
  applied.
- `pty:PATH` is intended for interactive programs that expect terminal behavior.
- `file:PATH` opens the file read/write and creates it with mode `0600` when it
  does not exist.
- Use `--hex`, `--json`, and `--timeout SEC` with relay mode for inspection and
  automation.

Relay examples:

```sh
wcat relay - tcp:example.com:80
wcat relay listen:127.0.0.1:9000 tcp:10.0.0.5:22
wcat relay unix-listen:/tmp/wcat.sock exec:/usr/bin/tee
wcat relay - exec:/usr/bin/tee
wcat relay tcp:127.0.0.1:9000 file:./capture.bin
wcat relay listen:0.0.0.0:4444 pty:/bin/sh
wcat relay --hex --timeout 10 tcp:127.0.0.1:8000 file:./trace.bin
```

## Project Layout

See [docs/architecture.md](docs/architecture.md) for the architecture plan,
feature mapping, and implementation roadmap.

See [docs/json-logging.md](docs/json-logging.md) for the structured log schema.

See [docs/fuzzing.md](docs/fuzzing.md) for fuzzing commands, seed corpus
details, and release fuzz expectations.

See [docs/reproducible-builds.md](docs/reproducible-builds.md) for package
determinism checks and release signing steps.

## Security Positioning

Wirecat is a general network utility. Version 1 explicitly avoids C2 framework
behavior, persistence, stealth, offensive automation, and embedded scripting.
The useful security-professional workflows are standard transport inspection,
debugging, secure relays, controlled shell/process bridging, and file movement.

## Packaging

The `debian/` directory contains packaging metadata prepared for review. Before
upload to a distribution, finalize maintainer identity, changelog versioning,
and reproducible build checks.
