# JSON Logging

`wcat --json` emits one JSON object per log event on standard error. Data bytes
remain on standard output unless a selected mode explicitly writes to a file,
process, or peer stream.

## Schema

Each record has these fields:

```json
{
  "ts": 1785477232,
  "level": "info",
  "event": "listen",
  "message": "listening on 127.0.0.1:4444"
}
```

Field meanings:

- `ts`: Unix timestamp in seconds.
- `level`: `error`, `warn`, `info`, or `debug`.
- `event`: Stable event category.
- `message`: Human-readable event detail.

## Current Events

Common event values:

- `accept`
- `broker_join`
- `broker_listen`
- `connect`
- `file_open`
- `listen`
- `proxy`
- `proxy_parse`
- `relay_accept`
- `relay_connect`
- `relay_file`
- `relay_listen`
- `relay_spec`
- `resolve`
- `signal`
- `timeout`
- `tls_ca`
- `tls_certificate`
- `tls_context`
- `tls_handshake`
- `tls_init`
- `tls_session`
- `tls_verify`

## Compatibility Rules

- New fields may be added in later releases.
- Existing field names and basic value types should remain stable.
- Automation should ignore unknown fields.
- Traffic hex dumps are diagnostic text, not JSON records.

