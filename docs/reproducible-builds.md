# Reproducible Builds and Signing

Wirecat's Debian package build uses Debian hardening flags through
`dpkg-buildflags` and inherits Debian's `SOURCE_DATE_EPOCH` handling from
`debian/changelog`.

## Local Determinism Check

When `reprotest` is unavailable, perform two clean binary package builds and
compare the generated package hashes:

```sh
make clean
dpkg-buildpackage -us -uc -b
mkdir -p tmp/repro-build-1
cp ../wirecat_*.deb tmp/repro-build-1/
cp ../wirecat-dbgsym_*.deb tmp/repro-build-1/

make clean
dpkg-buildpackage -us -uc -b
mkdir -p tmp/repro-build-2
cp ../wirecat_*.deb tmp/repro-build-2/
cp ../wirecat-dbgsym_*.deb tmp/repro-build-2/

sha256sum tmp/repro-build-1/*.deb tmp/repro-build-2/*.deb
```

The hashes for matching package names must be identical. For a distribution
upload, prefer running `reprotest` and inspecting any mismatch with
`diffoscope`.

## Release Signing

Release signing must use Chokri Hammedi's private GPG key. Do not generate or
store release keys in this repository.

Recommended release sequence:

```sh
make clean
make test
make analyze
make fuzz-cli FUZZ_TIME=3600
dpkg-buildpackage -S -sa
debsign ../wirecat_*.changes
git tag -s v0.1.0 -m "wirecat 0.1.0"
```

Verify signatures before publishing:

```sh
debsign --verify ../wirecat_*.changes
git tag -v v0.1.0
```

Binary package builds for local testing can continue to use:

```sh
dpkg-buildpackage -us -uc -b
```

## Latest Local Result

Environment:

- Date: 2026-08-01
- Package version: `wirecat 0.1.0-1`
- Host architecture: `amd64`
- Method: repeated clean `dpkg-buildpackage -us -uc -b` builds with SHA-256
  comparison of generated `.deb` artifacts

Result:

```text
5520630e72c02cc2a936179181430334f1abbd186d91a0d9425937901e2d1333  wirecat_0.1.0-1_amd64.deb
543b1cab6276db909b501b1adb72a66ce3583cf6fcb71af9e09ea6ff245e1bf4  wirecat-dbgsym_0.1.0-1_amd64.deb
```

Both hashes matched across clean rebuilds. `dpkg-genbuildinfo` emitted an
environment warning about an unrelated unreadable `/usr/local/lib/ollama/`
directory, but package generation completed and the `.deb` outputs were
reproducible under this local check.

Signing status:

- Debian source/package signing: pending Chokri Hammedi's private GPG key.
- Git release tag signing: pending Chokri Hammedi's private GPG key.
