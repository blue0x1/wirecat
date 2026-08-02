# Wirecat

[![CI](https://github.com/blue0x1/wirecat/actions/workflows/ci.yml/badge.svg)](https://github.com/blue0x1/wirecat/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/blue0x1/wirecat?sort=semver)](https://github.com/blue0x1/wirecat/releases/latest)
[![Total Downloads](https://img.shields.io/github/downloads/blue0x1/wirecat/total)](https://github.com/blue0x1/wirecat/releases)
[![License](https://img.shields.io/github/license/blue0x1/wirecat)](LICENSE)
[![Language](https://img.shields.io/badge/language-C-555555.svg)](https://github.com/blue0x1/wirecat)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20POSIX-informational)](README.md)

**Wirecat (`wcat`) is a native C stream and session utility for connecting,
listening, relaying, proxying, transferring files, and handling interactive
sessions across modern Linux/POSIX transports.**

It combines a netcat-style command surface with TLS/mTLS, QUIC, Unix sockets,
SCTP, VSOCK, proxy support, PTY-backed execution, broker/chat mode, JSON logs,
and hex inspection.


## Install

Download packages and archives from the
[latest release](https://github.com/blue0x1/wirecat/releases/latest).

Debian/Kali/Ubuntu amd64:

```sh
sudo apt install ./wirecat_0.1.0-1_amd64.deb
```

Standalone Linux amd64:

```sh
tar -xzf wirecat-0.1.0-linux-amd64.tar.gz
sudo install -m 0755 wirecat-0.1.0-linux-amd64/wcat /usr/local/bin/wcat
wcat --version
```

Build from source:

```sh
sudo apt install build-essential pkg-config libssl-dev
make
make test
```

## Capabilities

| Area | Support |
| --- | --- |
| Transports | TCP, UDP, SCTP, Unix domain sockets, Linux VSOCK, IPv4, IPv6 |
| Security | TLS, mTLS, default client verification, custom CA/SNI/ALPN |
| Modern protocols | QUIC single-stream transport with OpenSSL QUIC APIs |
| Proxying | SOCKS5, HTTP CONNECT client mode, HTTP CONNECT proxy server |
| Sessions | stdio relay, `--exec`, POSIX PTY, shell-friendly interactive handling |
| Movement | file send/receive, file relay endpoint, hex inspection |
| Coordination | broker/chat mode, labels, control-byte escaping, client limits |
| Automation | JSON logs, clear exit codes, timeouts, signal handling, CIDR allow/deny |

## Why Wirecat

Wirecat is built as one small native binary with predictable behavior and no
runtime language dependency. The focus is practical operator workflows:
transport inspection, secure relays, controlled shell/process bridging, file
movement, and automation-friendly logging.

It is POSIX-first, dependency-conscious, and structured for Debian/Kali
packaging. TLS and QUIC support are provided through OpenSSL; QUIC requires an
OpenSSL build that exposes the QUIC APIs.

## Release Assets

The `0.1.0` release provides:

- Debian package: `wirecat_0.1.0-1_amd64.deb`
- Standalone Linux amd64 archive: `wirecat-0.1.0-linux-amd64.tar.gz`
- Source archive: `wirecat-0.1.0-source.tar.gz`
- Checksums: `SHA256SUMS`

Release notes are in [RELEASE.md](RELEASE.md).

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

## Usage

Wirecat uses subcommands for the main workflows:

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

## Examples

Basic TCP:

```sh
wcat connect example.com 80
wcat --version
wcat listen 0.0.0.0 4444
wcat listen --keep-open 0.0.0.0 4444
```

TLS and QUIC:

```sh
wcat connect --tls example.com 443
wcat connect --quic --alpn h3 example.com 443
wcat connect --tls --ca-file ./ca.pem --sni service.example service.example 443
wcat connect --tls --ca-file ./ca.pem --sni service.example --client-cert client.crt --client-key client.key service.example 443
wcat listen --tls --cert server.crt --key server.key 0.0.0.0 8443
wcat listen --tls --require-client-cert --ca-file ./clients-ca.pem --cert server.crt --key server.key 0.0.0.0 8443
wcat listen --quic --cert server.crt --key server.key 0.0.0.0 8443
wcat listen --quic --tls-insecure --cert server.crt --key server.key --pty --exec /bin/bash 127.0.0.1 8443
```

Access control:

```sh
wcat listen --allow 192.0.2.0/24 0.0.0.0 4444
wcat listen --deny 198.51.100.0/24 0.0.0.0 4444
```

Proxying:

```sh
wcat connect --proxy socks5://127.0.0.1:9050 example.com 80
wcat connect --proxy http://proxy.local:8080 example.com 443
wcat proxy 127.0.0.1 3128
```

Local and specialized transports:

```sh
wcat listen --unix --exec /usr/bin/tee /tmp/wcat.sock
wcat connect --unix /tmp/wcat.sock
wcat listen --sctp 0.0.0.0 5555
wcat connect --sctp 127.0.0.1 5555
wcat listen --vsock any 5555
wcat connect --vsock 2 5555
```

PTY-backed execution:

```sh
wcat listen --pty --exec /bin/bash 0.0.0.0 4444
wcat listen --quic --tls-insecure --cert server.crt --key server.key --pty --exec /bin/bash 127.0.0.1 8443
```

File movement:

```sh
wcat send ./archive.tar 192.0.2.10 9000
wcat recv ./archive.tar 0.0.0.0 9000
```

Broker/chat:

```sh
wcat broker 0.0.0.0 5555
wcat broker --chat 0.0.0.0 5555
wcat broker --chat --max-clients 16 --broker-buffer 131072 0.0.0.0 5555
```

Automation and inspection:

```sh
wcat connect --json --hex example.com 80
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

```text
include/     shared project headers
src/         implementation modules
tests/       unit, integration, and fuzz harness sources
docs/        architecture, logging, fuzzing, reproducible build notes, man page
debian/      Debian packaging metadata
```

More documentation:

- [Architecture](docs/architecture.md)
- [JSON logging schema](docs/json-logging.md)
- [Fuzzing](docs/fuzzing.md)
- [Reproducible builds and signing](docs/reproducible-builds.md)
- [Manual page](docs/wcat.1.md)

## Security Positioning

Wirecat is a general network utility. It is intended for standard transport
inspection, debugging, secure relays, controlled shell/process bridging, and
file movement.

It intentionally avoids C2 framework behavior, persistence, stealth, offensive
automation, and embedded scripting.

## Responsible Use

Use Wirecat only on systems and networks that you own, administer, or have
explicit permission to test. The project is provided for lawful administration,
debugging, research, and educational use.

You are responsible for how you use this software. The author and contributors
are not responsible for misuse, damage, unauthorized access, policy violations,
or illegal activity performed with Wirecat.

## Packaging

The `debian/` directory contains packaging metadata for Debian/Kali-style
builds. Build packages with:

```sh
dpkg-buildpackage -us -uc -b
```

Before distribution upload, sign release artifacts with the maintainer GPG key
and verify reproducible build output as described in
[docs/reproducible-builds.md](docs/reproducible-builds.md).

## License

Wirecat is released under the [MIT License](LICENSE).

Author: [Chokri Hammedi (`blue0x1`)](https://github.com/blue0x1)
