# Wirecat Architecture

## Product Identity

Wirecat is a modern native stream and session utility. The core experience is a
single predictable binary for connecting, listening, relaying, proxying,
transferring files, inspecting traffic, and handling interactive sessions.

## Directory Tree

```text
.
├── Makefile
├── README.md
├── debian/
│   ├── changelog
│   ├── control
│   ├── copyright
│   ├── rules
│   └── source/format
├── docs/
│   ├── architecture.md
│   ├── json-logging.md
│   ├── wcat.1
│   └── wcat.1.md
├── include/
│   ├── broker.h
│   ├── cli.h
│   ├── filexfer.h
│   ├── log.h
│   ├── process.h
│   ├── proxy.h
│   ├── relay.h
│   ├── signalx.h
│   ├── socketx.h
│   ├── tls.h
│   └── util.h
└── src/
    ├── broker.c
    ├── cli.c
    ├── filexfer.c
    ├── log.c
    ├── main.c
    ├── process.c
    ├── proxy.c
    ├── relay.c
    ├── signalx.c
    ├── socketx.c
    ├── tls.c
    └── util.c
```

## Module Responsibilities

| Feature | Main module | Supporting modules |
| --- | --- | --- |
| TCP client | `socketx` | `cli`, `relay`, `log` |
| TCP listen | `socketx` | `signalx`, `relay`, `log` |
| UDP client | `socketx` | `relay`, `log` |
| UDP listen | `socketx` | `relay`, `log` |
| IPv4/IPv6 | `socketx` | `cli` |
| Unix domain sockets | `socketx` | `main`, `broker`, `relay` |
| SCTP stream sockets | `socketx` | `main`, `broker`, `cli` |
| Linux AF_VSOCK | `socketx` | `main`, `broker`, `cli` |
| TLS client | `tls` | `socketx`, `relay`, `cli` |
| TLS server | `tls` | `socketx`, `relay` |
| TLS client certificates | `tls` | `cli`, `filexfer`, `main` |
| QUIC single-stream transport | `quic` | `tls`, `relay`, `cli` |
| Listener access control | `access` | `main`, `broker`, `filexfer` |
| SOCKS5 proxy | `proxy` | `socketx`, `util` |
| HTTP CONNECT proxy | `proxy` | `socketx`, `util` |
| HTTP CONNECT proxy server | `proxy` | `socketx`, `relay`, `access` |
| Socket-to-socket relay | `relay` | `socketx`, `tls` |
| Socket-to-process relay | `process`, `relay` | `signalx` |
| Process-to-socket relay | `process`, `relay` | `signalx` |
| File-to-socket | `filexfer`, `relay` | `socketx` |
| Socket-to-file | `filexfer`, `relay` | `socketx` |
| PTY shell | `process` | `relay`, `signalx` |
| Send/receive file mode | `filexfer` | `socketx`, `tls`, `proxy` |
| Keep-open listener | `main`, `socketx` | `signalx` |
| Broker/chat | `broker` | `socketx`, `relay` |
| Hex dump | `log` | `relay` |
| Timeout controls | `socketx`, `relay` | `cli`, `util` |
| JSON logging | `log` | all modules |
| Signal handling | `signalx` | `main`, `relay`, `broker` |
| Help/manpage CLI | `cli` | `docs/wcat.1.md` |

## Architecture Plan

The binary starts in `main.c`, initializes logging and signal handling, then
dispatches to a subcommand parsed by `cli.c`.

`socketx.c` owns address resolution, socket creation, TCP/UDP/SCTP
connect/listen, Unix domain sockets, Linux AF_VSOCK, and accepting
connections. It exposes a small API that hides transport and socket option
details.

`tls.c` wraps OpenSSL behind a `wcat_stream` interface. Client verification is
enabled by default and can be configured with explicit CA and SNI options. Plain
sockets and TLS sockets are both consumed by `relay.c`, so most transfer logic
does not care whether a peer is encrypted.

Server mode can require verified client certificates with
`--require-client-cert --ca-file FILE`. Client mode can present a certificate
with `--client-cert FILE --client-key FILE`.

`quic.c` implements single-stream QUIC connect/listen support when the linked
OpenSSL build exposes QUIC APIs. It uses a real bidirectional QUIC stream and
shares TLS verification, client certificate, SNI, ALPN, and relay behavior.
Builds without OpenSSL QUIC support keep the CLI visible but return a clear
runtime error for `--quic`.

`access.c` implements exact-IP and CIDR checks for accepted TCP peers. Deny
rules are evaluated before allow rules. The module intentionally avoids hostname
policy in v1 so decisions are based on the peer address accepted by the kernel.

`proxy.c` implements outbound proxy negotiation after opening a TCP connection
to the proxy. The caller still receives a connected socket to the final target.

`relay.c` contains the bidirectional pump. It uses `poll(2)` first because it is
portable and adequate for v1. The public API should allow an epoll backend later
without changing command handling.

Relay command endpoint grammar:

```text
-                    standard input/output
stdio                standard input/output
tcp:HOST:PORT        outbound TCP connection
listen:HOST:PORT     inbound TCP listener, accepts one peer
file:PATH            read/write file endpoint, created if missing
exec:PATH            process endpoint using pipes
pty:PATH             process endpoint using a POSIX PTY
```

The current grammar is intentionally small. It should stay stable while future
transport types are added behind the same endpoint abstraction.

`process.c` starts subprocesses either over pipes or a POSIX PTY. PTY mode is
the default recommendation for interactive shells because line discipline,
terminal sizing, and job-control behavior are more stable.

`broker.c` implements a bounded multi-peer chat broker. Connected clients are
nonblocking and receive buffered fan-out, so a slow receiver cannot stall every
other peer. Operators can set `--max-clients` and `--broker-buffer` to keep
resource use predictable. Plain broker mode relays raw bytes. `--chat` adds
client labels and escapes terminal control bytes for multi-user terminal chat.
It is not a C2 component; it broadcasts bytes between connected users for
debugging, collaboration, CTFs, and manual testing.

`log.c` provides human and JSON structured events. It also owns hex-dump output
so traffic inspection formatting is consistent.

## CLI Examples

```sh
wcat connect example.com 80
wcat connect -u 192.0.2.10 53
wcat listen -k 0.0.0.0 4444
wcat listen --tls --cert cert.pem --key key.pem :: 8443
wcat connect --proxy socks5://127.0.0.1:9050 example.org 80
wcat proxy 127.0.0.1 3128
wcat listen --unix --exec /usr/bin/tee /tmp/wcat.sock
wcat connect --sctp 127.0.0.1 5555
wcat listen --vsock any 5555
wcat listen --exec /usr/bin/tee 127.0.0.1 9001
wcat listen --pty --exec /bin/bash 0.0.0.0 4444
wcat send ./payload.bin host.local 9000
wcat recv ./payload.bin 0.0.0.0 9000
wcat relay listen:127.0.0.1:9000 tcp:10.0.0.5:22
wcat relay unix-listen:/tmp/wcat.sock exec:/usr/bin/tee
wcat relay listen:0.0.0.0:4444 pty:/bin/sh
wcat broker --unix --chat /tmp/wcat-chat.sock
```

## Phased Roadmap

### Phase 0: Foundation

- Establish source layout, Makefile, headers, coding style, docs, packaging
  skeleton, and compile checks.
- Implement CLI parser, logging, signals, TCP/UDP primitives, and relay loop.

### Phase 1: Required v1 Core

- Harden TCP/UDP connect/listen behavior.
- Finish TLS client/server verification controls and useful defaults.
- Complete SOCKS5 and HTTP CONNECT proxy paths.
- Add file send/receive workflows and socket/process relay.
- Add PTY-backed process mode for Linux.
- Add JSON logs, hex dumps, timeouts, and keep-open listeners.
- Add broker/chat mode.

### Phase 2: Release Readiness

- Expand unit tests for parsers and integration tests for local loopback.
- Maintain sanitizer and static-analysis targets.
- Keep the roff manpage and Markdown reference synchronized.
- Add CI for gcc, clang, ASan, UBSan, and Debian package builds.
- Add static-analysis and fuzz-harness build targets.
- Validate hardening flags and reproducible builds.

### Phase 3: Best-of-Breed Improvements

- Add a compact stream-spec grammar for advanced relay expressions.
- Add structured event IDs and stable JSON schema documentation.
- Add connection profiles for repeated workflows.
- Expand policy-based TLS verification modes.
- Add access controls, compression, UNIX sockets, and multiplexing.
- Prepare Windows abstractions for sockets and ConPTY.

## Debian/Kali Packaging Notes

- Keep dependencies small: `libssl-dev`, libc, and standard build tools.
- Install the binary as `/usr/bin/wcat`.
- Install documentation in `/usr/share/doc/wirecat`.
- Install the manpage as `/usr/share/man/man1/wcat.1.gz`.
- Use Debian hardening flags through `dpkg-buildflags`.
- Add autopkgtests that run loopback TCP, UDP, TLS, and file-transfer cases.
- Ensure `debian/copyright` lists all files and licenses accurately before
  publication.
- Avoid vendored dependencies.
- Keep release tarballs reproducible and signed.

## How To Make It Best Of Breed

- Reliability first: deterministic exits, clear errors, no surprising half-open
  behavior, and graceful signal shutdown.
- UX discipline: common flows should be one command, advanced flows should be
  discoverable, and errors should suggest the broken input.
- Stream abstraction: every transport should be usable by the relay engine
  without special cases leaking into command handling.
- Scriptability: JSON logs, stable exit codes, quiet mode, and machine-readable
  errors should be treated as first-class surfaces.
- Operational security without stealth: safe TLS defaults, no persistence, no
  hidden automation, and visible behavior.
- Test realism: integration tests must exercise PTYs, TLS, proxies, large files,
  IPv6, timeouts, and interrupted sessions.
- Maintainability: small files, explicit ownership boundaries, and no clever
  macros that make future audits harder.
