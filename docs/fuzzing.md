# Fuzzing

Wirecat includes a libFuzzer harness for CLI parsing and option validation.
The harness exercises `wcat_parse_args()` with tokenized arbitrary input and is
intended to catch parser crashes, undefined behavior, and sanitizer failures.

## Build

```sh
make fuzz-harness
```

## Run

The default production fuzz target runs for one hour:

```sh
make fuzz-cli
```

For shorter local checks, override `FUZZ_TIME`:

```sh
make fuzz-cli FUZZ_TIME=60
```

The corpus lives in `tests/corpus/cli/`. It started with representative valid
and invalid commands for connect, listen, QUIC, broker, relay, and ACL parsing,
and is allowed to retain coverage-increasing inputs from local fuzz runs.

## Release Expectation

Before tagging a release, run:

```sh
make clean
make fuzz-cli FUZZ_TIME=3600
```

Record the libFuzzer final stats, compiler, sanitizer set, and OpenSSL version
in the release notes. A passing run means the fuzz target exits normally with no
crash artifact and no AddressSanitizer or UndefinedBehaviorSanitizer finding.

## Latest Local Result

Environment:

- Date: 2026-08-01
- Compiler: Debian clang 19.1.7
- Sanitizers: libFuzzer, AddressSanitizer, UndefinedBehaviorSanitizer
- Target: `tests/fuzz_cli`
- Corpus: `tests/corpus/cli`

Command:

```sh
make fuzz-cli FUZZ_TIME=3600
```

Result:

- Status: pass
- Log: `tmp/fuzz-cli-3600.log`
- Executed units: 582,830,506
- Runtime: 3,601 seconds
- Average executions per second: 161,852
- Coverage counters: 425
- Feature count: 1,259
- Active corpus reported by libFuzzer: 278 files, 10,019 bytes
- Retained on-disk corpus after the run: 1,028 files, 77,444 bytes
- New units added: 205
- Slowest unit: 0 seconds
- Peak RSS: 592 MB
- Crash artifacts: none
- ASan/UBSan findings: none

## Follow-Up Parser Smoke

After adding `proxy`, `--unix`, `--sctp`, and `--vsock` parsing, a short
sanitizer-backed fuzz smoke was run against the expanded CLI surface.

Command:

```sh
make fuzz-cli FUZZ_TIME=10
```

Result:

- Status: pass
- Executed units: 1,976,797
- Runtime: 11 seconds
- Average executions per second: 179,708
- Coverage counters: 520
- Feature count: 1,406
- Active corpus reported by libFuzzer: 317 files, 11,129 bytes
- Retained on-disk corpus after the smoke: 1,073 files, 79,390 bytes
- New units added: 234
- Slowest unit: 0 seconds
- Peak RSS: 478 MB
- Crash artifacts: none
- ASan/UBSan findings: none
