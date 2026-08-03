#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMPDIR="$ROOT/tmp/test-run"
WCAT="$ROOT/wcat"

mkdir -p "$TMPDIR"

fail() {
    echo "not ok - $1" >&2
    exit 1
}

ok() {
    echo "ok - $1"
}

wait_file() {
    file=$1
    i=0
    while [ "$i" -lt 50 ]; do
        [ -s "$file" ] && return 0
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

cleanup() {
    for pid in ${PIDS:-}; do
        kill "$pid" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

"$WCAT" --help | grep 'connect \[options\]' >/dev/null || fail "help output"
"$WCAT" --help | grep 'Relay endpoints:' >/dev/null || fail "relay grammar help"
"$WCAT" --help | grep -- '--max-clients' >/dev/null || fail "broker limit help"
"$WCAT" --help | grep -- '--chat' >/dev/null || fail "broker chat help"
"$WCAT" --help | grep -- '--multi' >/dev/null || fail "multi listen help"
"$WCAT" --help | grep -- '--quic' >/dev/null || fail "quic help"
"$WCAT" --help | grep -- '--unix' >/dev/null || fail "unix help"
"$WCAT" --help | grep 'proxy   \[options\]' >/dev/null || fail "proxy help"
ok "help"

"$WCAT" listen --exec /usr/bin/tee 127.0.0.1 46101 >"$TMPDIR/tcp.out" 2>"$TMPDIR/tcp.err" &
PIDS="${PIDS:-} $!"
sleep 0.2
printf 'tcp-ok\n' | "$WCAT" connect --timeout 2 127.0.0.1 46101 >"$TMPDIR/tcp.client" 2>"$TMPDIR/tcp.client.err"
grep 'tcp-ok' "$TMPDIR/tcp.client" >/dev/null || fail "tcp echo"
ok "tcp process relay"

"$WCAT" listen --allow 127.0.0.1/32 --exec /usr/bin/tee 127.0.0.1 46117 >"$TMPDIR/allow.out" 2>"$TMPDIR/allow.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'allow-ok\n' | "$WCAT" connect --timeout 2 127.0.0.1 46117 >"$TMPDIR/allow.client" 2>"$TMPDIR/allow.client.err"
grep 'allow-ok' "$TMPDIR/allow.client" >/dev/null || fail "allow list accept"
ok "allow list"

"$WCAT" listen --deny 127.0.0.1/32 --exec /usr/bin/tee 127.0.0.1 46118 >"$TMPDIR/deny.out" 2>"$TMPDIR/deny.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'deny-drop\n' | "$WCAT" connect --timeout 1 127.0.0.1 46118 >"$TMPDIR/deny.client" 2>"$TMPDIR/deny.client.err" || true
grep 'denied peer' "$TMPDIR/deny.err" >/dev/null || fail "deny list reject"
ok "deny list"

rm -f "$TMPDIR/wcat.sock"
"$WCAT" listen --unix --exec /usr/bin/tee "$TMPDIR/wcat.sock" >"$TMPDIR/unix.out" 2>"$TMPDIR/unix.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'unix-ok\n' | "$WCAT" connect --unix --timeout 2 "$TMPDIR/wcat.sock" >"$TMPDIR/unix.client" 2>"$TMPDIR/unix.client.err"
grep 'unix-ok' "$TMPDIR/unix.client" >/dev/null || fail "unix socket echo"
ok "unix socket"

"$WCAT" listen 127.0.0.1 46108 >"$TMPDIR/sig.out" 2>"$TMPDIR/sig.err" &
sigpid=$!
PIDS="$PIDS $sigpid"
sleep 0.2
kill -INT "$sigpid"
wait "$sigpid" || fail "listener signal shutdown"
ok "signal shutdown"

"$WCAT" listen -u 127.0.0.1 46102 >"$TMPDIR/udp.out" 2>"$TMPDIR/udp.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'udp-ok\n' | "$WCAT" connect -u --timeout 1 127.0.0.1 46102 >/dev/null 2>"$TMPDIR/udp.client.err" || true
wait_file "$TMPDIR/udp.out" || fail "udp receive"
grep 'udp-ok' "$TMPDIR/udp.out" >/dev/null || fail "udp payload"
ok "udp"

printf 'file-ok\n' >"$TMPDIR/send.txt"
"$WCAT" recv "$TMPDIR/recv.txt" 127.0.0.1 46103 >"$TMPDIR/recv.out" 2>"$TMPDIR/recv.err" &
PIDS="$PIDS $!"
sleep 0.2
"$WCAT" send "$TMPDIR/send.txt" 127.0.0.1 46103 >/dev/null 2>"$TMPDIR/send.err"
sleep 0.2
cmp "$TMPDIR/send.txt" "$TMPDIR/recv.txt" || fail "file transfer"
ok "file transfer"

dd if=/dev/zero of="$TMPDIR/large-send.bin" bs=1024 count=256 >/dev/null 2>&1
"$WCAT" recv "$TMPDIR/large-recv.bin" 127.0.0.1 46110 >"$TMPDIR/large.recv.out" 2>"$TMPDIR/large.recv.err" &
PIDS="$PIDS $!"
sleep 0.2
"$WCAT" send "$TMPDIR/large-send.bin" 127.0.0.1 46110 >/dev/null 2>"$TMPDIR/large.send.err"
sleep 0.2
cmp "$TMPDIR/large-send.bin" "$TMPDIR/large-recv.bin" || fail "large file transfer"
ok "large file transfer"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/key.pem" \
    -out "$TMPDIR/cert.pem" \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -days 1 >/dev/null 2>&1
"$WCAT" listen --tls --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" --exec /usr/bin/tee 127.0.0.1 46104 >"$TMPDIR/tls.out" 2>"$TMPDIR/tls.err" &
PIDS="$PIDS $!"
sleep 0.2
if printf 'tls-verify-fail\n' | "$WCAT" connect --tls --timeout 2 127.0.0.1 46104 >"$TMPDIR/tls.verify" 2>"$TMPDIR/tls.verify.err"; then
    fail "tls verification should reject self-signed certificate"
fi
ok "tls verification failure"

"$WCAT" listen --tls --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" --exec /usr/bin/tee 127.0.0.1 46104 >"$TMPDIR/tls.out" 2>"$TMPDIR/tls.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'tls-ok\n' | "$WCAT" connect --tls-insecure --timeout 2 127.0.0.1 46104 >"$TMPDIR/tls.client" 2>"$TMPDIR/tls.client.err"
grep 'tls-ok' "$TMPDIR/tls.client" >/dev/null || fail "tls echo"
ok "tls"

"$WCAT" listen --tls --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" --exec /usr/bin/tee 127.0.0.1 46111 >"$TMPDIR/tls.ca.out" 2>"$TMPDIR/tls.ca.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'tls-ca-ok\n' | "$WCAT" connect --tls --ca-file "$TMPDIR/cert.pem" --sni localhost --timeout 2 127.0.0.1 46111 >"$TMPDIR/tls.ca.client" 2>"$TMPDIR/tls.ca.client.err"
grep 'tls-ca-ok' "$TMPDIR/tls.ca.client" >/dev/null || fail "tls ca verification success"
ok "tls ca verification"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/ca.key" \
    -out "$TMPDIR/ca.pem" \
    -subj /CN=wcat-test-ca \
    -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/mtls-server.key" \
    -out "$TMPDIR/mtls-server.csr" \
    -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$TMPDIR/mtls-server.ext"
openssl x509 -req \
    -in "$TMPDIR/mtls-server.csr" \
    -CA "$TMPDIR/ca.pem" \
    -CAkey "$TMPDIR/ca.key" \
    -CAcreateserial \
    -out "$TMPDIR/mtls-server.pem" \
    -days 1 \
    -extfile "$TMPDIR/mtls-server.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/client.key" \
    -out "$TMPDIR/client.csr" \
    -subj /CN=wcat-client >/dev/null 2>&1
openssl x509 -req \
    -in "$TMPDIR/client.csr" \
    -CA "$TMPDIR/ca.pem" \
    -CAkey "$TMPDIR/ca.key" \
    -CAcreateserial \
    -out "$TMPDIR/client.pem" \
    -days 1 >/dev/null 2>&1
"$WCAT" listen --tls --require-client-cert --ca-file "$TMPDIR/ca.pem" --cert "$TMPDIR/mtls-server.pem" --key "$TMPDIR/mtls-server.key" --exec /usr/bin/tee 127.0.0.1 46115 >"$TMPDIR/mtls.reject.out" 2>"$TMPDIR/mtls.reject.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'mtls-no-client\n' | "$WCAT" connect --tls --ca-file "$TMPDIR/ca.pem" --sni localhost --timeout 2 127.0.0.1 46115 >"$TMPDIR/mtls.reject.client" 2>"$TMPDIR/mtls.reject.client.err" || true
grep 'peer did not return a certificate' "$TMPDIR/mtls.reject.err" >/dev/null || fail "mtls should reject missing client certificate"
ok "mtls client cert required"

"$WCAT" listen --tls --require-client-cert --ca-file "$TMPDIR/ca.pem" --cert "$TMPDIR/mtls-server.pem" --key "$TMPDIR/mtls-server.key" --exec /usr/bin/tee 127.0.0.1 46116 >"$TMPDIR/mtls.out" 2>"$TMPDIR/mtls.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'mtls-ok\n' | "$WCAT" connect --tls --ca-file "$TMPDIR/ca.pem" --sni localhost --client-cert "$TMPDIR/client.pem" --client-key "$TMPDIR/client.key" --timeout 2 127.0.0.1 46116 >"$TMPDIR/mtls.client" 2>"$TMPDIR/mtls.client.err"
grep 'mtls-ok' "$TMPDIR/mtls.client" >/dev/null || fail "mtls echo"
ok "mtls"

"$WCAT" listen --quic --tls-insecure --cert "$TMPDIR/cert.pem" --key "$TMPDIR/key.pem" --exec /bin/bash 127.0.0.1 46119 >"$TMPDIR/quic.out" 2>"$TMPDIR/quic.err" &
quicpid=$!
PIDS="$PIDS $quicpid"
sleep 0.3
if grep 'OpenSSL was built without QUIC support' "$TMPDIR/quic.err" >/dev/null 2>&1; then
    echo "skip - quic unavailable"
else
    printf 'printf "quic-ok\\n"\nexit\n' | "$WCAT" connect --quic --tls-insecure --timeout 3 127.0.0.1 46119 >"$TMPDIR/quic.client" 2>"$TMPDIR/quic.client.err"
    grep 'quic-ok' "$TMPDIR/quic.client" >/dev/null || fail "quic process relay"
    ok "quic"
fi

"$WCAT" listen --json --hex --exec /usr/bin/tee 127.0.0.1 46112 >"$TMPDIR/json.out" 2>"$TMPDIR/json.err" &
PIDS="$PIDS $!"
sleep 0.2
printf 'json-ok\n' | "$WCAT" connect --timeout 2 127.0.0.1 46112 >"$TMPDIR/json.client" 2>"$TMPDIR/json.client.err"
grep 'json-ok' "$TMPDIR/json.client" >/dev/null || fail "json relay data"
grep '"event":"listen"' "$TMPDIR/json.err" >/dev/null || fail "json listen event"
grep '6a 73 6f 6e 2d 6f 6b 0a' "$TMPDIR/json.err" >/dev/null || fail "hex dump"
ok "json and hex"

"$WCAT" listen --pty --exec /bin/sh 127.0.0.1 46109 >"$TMPDIR/pty.server" 2>"$TMPDIR/pty.server.err" &
PIDS="$PIDS $!"
sleep 0.2
printf "printf 'pty-ok\\n'\nexit\n" | "$WCAT" connect --timeout 3 127.0.0.1 46109 >"$TMPDIR/pty.client" 2>"$TMPDIR/pty.client.err"
grep 'pty-ok' "$TMPDIR/pty.client" >/dev/null || fail "pty shell"
ok "pty shell"

"$ROOT/tests/stubs/socks5_stub" 46105 >"$TMPDIR/socks.out" 2>"$TMPDIR/socks.err" &
PIDS="$PIDS $!"
wait_file "$TMPDIR/socks.out" || fail "socks stub did not start"
printf 'socks-ok\n' | "$WCAT" connect --proxy socks5://127.0.0.1:46105 example.com 80 >"$TMPDIR/socks.client" 2>"$TMPDIR/socks.client.err"
grep 'socks-ok' "$TMPDIR/socks.client" >/dev/null || fail "socks proxy echo"
grep 'requested example.com:80' "$TMPDIR/socks.out" >/dev/null || fail "socks target"
ok "socks5 proxy"

"$ROOT/tests/stubs/http_connect_stub" 46106 >"$TMPDIR/http.out" 2>"$TMPDIR/http.err" &
PIDS="$PIDS $!"
wait_file "$TMPDIR/http.out" || fail "http stub did not start"
printf 'http-ok\n' | "$WCAT" connect --proxy http://127.0.0.1:46106 example.com 443 >"$TMPDIR/http.client" 2>"$TMPDIR/http.client.err"
grep 'http-ok' "$TMPDIR/http.client" >/dev/null || fail "http proxy echo"
grep 'requested example.com:443' "$TMPDIR/http.out" >/dev/null || fail "http target"
ok "http connect proxy"

"$WCAT" listen --exec /usr/bin/tee 127.0.0.1 46121 >"$TMPDIR/proxy.upstream.out" 2>"$TMPDIR/proxy.upstream.err" &
PIDS="$PIDS $!"
sleep 0.2
"$WCAT" proxy 127.0.0.1 46122 >"$TMPDIR/proxy.server.out" 2>"$TMPDIR/proxy.server.err" &
proxypid=$!
PIDS="$PIDS $proxypid"
sleep 0.2
printf 'proxy-server-ok\n' | "$WCAT" connect --proxy http://127.0.0.1:46122 --timeout 2 127.0.0.1 46121 >"$TMPDIR/proxy.server.client" 2>"$TMPDIR/proxy.server.client.err"
grep 'proxy-server-ok' "$TMPDIR/proxy.server.client" >/dev/null || fail "http connect proxy server"
kill -INT "$proxypid" >/dev/null 2>&1 || true
ok "http connect proxy server"

"$WCAT" relay - exec:/usr/bin/tee >"$TMPDIR/relay.out" 2>"$TMPDIR/relay.err" <<EOF
relay-ok
EOF
grep 'relay-ok' "$TMPDIR/relay.out" >/dev/null || fail "relay stdio process"
ok "relay"

rm -f "$TMPDIR/relay.sock"
"$WCAT" relay "unix-listen:$TMPDIR/relay.sock" exec:/usr/bin/tee >"$TMPDIR/relay.unix.out" 2>"$TMPDIR/relay.unix.err" &
relay_unix_pid=$!
PIDS="$PIDS $relay_unix_pid"
sleep 0.2
printf 'relay-unix-ok\n' | "$WCAT" connect --unix --timeout 2 "$TMPDIR/relay.sock" >"$TMPDIR/relay.unix.client" 2>"$TMPDIR/relay.unix.client.err"
grep 'relay-unix-ok' "$TMPDIR/relay.unix.client" >/dev/null || fail "relay unix process"
ok "relay unix"

if "$WCAT" listen -6 --exec /usr/bin/tee ::1 46113 >"$TMPDIR/ipv6.out" 2>"$TMPDIR/ipv6.err" &
then
    ipv6pid=$!
    PIDS="$PIDS $ipv6pid"
    sleep 0.2
    if printf 'ipv6-ok\n' | "$WCAT" connect -6 --timeout 2 ::1 46113 >"$TMPDIR/ipv6.client" 2>"$TMPDIR/ipv6.client.err"; then
        grep 'ipv6-ok' "$TMPDIR/ipv6.client" >/dev/null || fail "ipv6 echo"
        ok "ipv6"
    else
        echo "skip - ipv6 unavailable"
    fi
else
    echo "skip - ipv6 unavailable"
fi

"$WCAT" broker 127.0.0.1 46107 >"$TMPDIR/broker.out" 2>"$TMPDIR/broker.err" &
brokerpid=$!
PIDS="$PIDS $brokerpid"
sleep 0.2
(sleep 0.5) | "$WCAT" connect --timeout 2 127.0.0.1 46107 >"$TMPDIR/broker.b" 2>"$TMPDIR/broker.b.err" &
bpid=$!
sleep 0.2
printf 'broker-ok\n' | "$WCAT" connect --timeout 1 127.0.0.1 46107 >/dev/null 2>"$TMPDIR/broker.a.err" || true
wait "$bpid" || true
grep 'broker-ok' "$TMPDIR/broker.b" >/dev/null || fail "broker broadcast"
kill -INT "$brokerpid" >/dev/null 2>&1 || true
ok "broker broadcast"

"$WCAT" broker --chat 127.0.0.1 46120 >"$TMPDIR/broker.chat.out" 2>"$TMPDIR/broker.chat.err" &
chatpid=$!
PIDS="$PIDS $chatpid"
sleep 0.2
(sleep 0.5) | "$WCAT" connect --timeout 2 127.0.0.1 46120 >"$TMPDIR/broker.chat.b" 2>"$TMPDIR/broker.chat.b.err" &
chat_b=$!
sleep 0.2
printf 'hello\001chat\n' | "$WCAT" connect --timeout 1 127.0.0.1 46120 >/dev/null 2>"$TMPDIR/broker.chat.a.err" || true
wait "$chat_b" || true
grep '<client2> hello\\x01chat' "$TMPDIR/broker.chat.b" >/dev/null || fail "broker chat labels and escapes"
kill -INT "$chatpid" >/dev/null 2>&1 || true
ok "broker chat"

"$WCAT" broker --max-clients 1 127.0.0.1 46114 >"$TMPDIR/broker.limit.out" 2>"$TMPDIR/broker.limit.err" &
limitpid=$!
PIDS="$PIDS $limitpid"
sleep 0.2
(sleep 1) | "$WCAT" connect --timeout 2 127.0.0.1 46114 >"$TMPDIR/broker.limit.a" 2>"$TMPDIR/broker.limit.a.err" &
limit_a=$!
sleep 0.2
printf 'limit-drop\n' | "$WCAT" connect --timeout 1 127.0.0.1 46114 >"$TMPDIR/broker.limit.b" 2>"$TMPDIR/broker.limit.b.err" || true
wait "$limit_a" || true
grep 'broker client limit reached' "$TMPDIR/broker.limit.err" >/dev/null || fail "broker client limit"
kill -INT "$limitpid" >/dev/null 2>&1 || true
ok "broker client limit"

"$WCAT" listen --multi --max-clients 4 127.0.0.1 46123 </dev/null >"$TMPDIR/multi.out" 2>"$TMPDIR/multi.err" &
multipid=$!
PIDS="$PIDS $multipid"
sleep 0.2
(printf 'multi-a\n'; sleep 0.4) | "$WCAT" connect --timeout 1 127.0.0.1 46123 >"$TMPDIR/multi.a" 2>"$TMPDIR/multi.a.err" || true &
multi_a=$!
(printf 'multi-b\n'; sleep 0.4) | "$WCAT" connect --timeout 1 127.0.0.1 46123 >"$TMPDIR/multi.b" 2>"$TMPDIR/multi.b.err" || true &
multi_b=$!
wait "$multi_a" || true
wait "$multi_b" || true
kill -INT "$multipid" >/dev/null 2>&1 || true
sleep 0.2
grep 'multi-a' "$TMPDIR/multi.out" >/dev/null || fail "multi session a"
grep 'multi-b' "$TMPDIR/multi.out" >/dev/null || fail "multi session b"
grep '\[session' "$TMPDIR/multi.out" >/dev/null || fail "multi session prefix"
ok "multi listen sessions"

(
    sleep 0.4
    printf ':rename 1 demo\n'
    printf ':info\n'
    printf ':i\n'
    sleep 1.5
    printf ':quit\n'
) | "$WCAT" listen --multi --max-clients 4 127.0.0.1 46125 >"$TMPDIR/multi.commands.out" 2>"$TMPDIR/multi.commands.err" &
multicmdpid=$!
PIDS="$PIDS $multicmdpid"
sleep 0.2
(sleep 0.7; printf 'renamed-output\n'; sleep 0.2) | "$WCAT" connect --timeout 3 127.0.0.1 46125 >"$TMPDIR/multi.commands.client" 2>"$TMPDIR/multi.commands.client.err" || true
wait "$multicmdpid" || true
grep 'renamed session 1' "$TMPDIR/multi.commands.err" >/dev/null || fail "multi rename command"
grep 'session.*1.*demo' "$TMPDIR/multi.commands.err" >/dev/null || fail "multi info active session"
grep '\[session1 demo ' "$TMPDIR/multi.commands.out" >/dev/null || fail "multi renamed output prefix"
ok "multi commands"

"$WCAT" listen --multi --max-clients 4 127.0.0.1 46124 </dev/null >"$TMPDIR/multi.http.out" 2>"$TMPDIR/multi.http.err" &
multihttppid=$!
PIDS="$PIDS $multihttppid"
sleep 0.2
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1:46124\r\n\r\n' | "$WCAT" connect --timeout 1 127.0.0.1 46124 >"$TMPDIR/multi.http.client" 2>"$TMPDIR/multi.http.client.err" || true
sleep 0.2
kill -INT "$multihttppid" >/dev/null 2>&1 || true
sleep 0.2
grep 'GET / HTTP' "$TMPDIR/multi.http.out" >/dev/null || fail "multi http request visible"
grep 'session 1 closed' "$TMPDIR/multi.http.err" >/dev/null || fail "multi http session closed"
ok "multi closes http sessions"

echo "all integration checks passed"
