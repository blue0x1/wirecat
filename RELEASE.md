# Release Checklist

1. Run `make clean`.
2. Run `make`.
3. Run `make CC=clang`.
4. Run `make test`.
5. Run `make asan`.
6. Run `make test` against the sanitizer build.
7. Run `make analyze`.
8. Run `make fuzz-harness`.
9. Run `make fuzz-cli FUZZ_TIME=3600` and record final libFuzzer stats.
10. Build the Debian package with hardening enabled.
11. Verify installed files:
   - `/usr/bin/wcat`
   - `/usr/share/man/man1/wcat.1`
12. Review `README.md`, `docs/wcat.1.md`, `docs/wcat.1`,
   `docs/json-logging.md`, `docs/fuzzing.md`, and
   `docs/reproducible-builds.md` for CLI sync.
13. Update `debian/changelog`.
14. Run two clean `dpkg-buildpackage -us -uc -b` builds and compare `.deb`
   SHA-256 hashes, or run `reprotest` when available.
15. Run `dpkg-buildpackage -S -sa`.
16. Sign the source upload with `debsign`.
17. Tag and sign the release with `git tag -s`.

## Reproducibility Notes

- Build with Debian hardening flags through `debian/rules`.
- Avoid generated files in the source archive.
- Keep dependency versions visible in the generated `.buildinfo`.
- Prefer clean builds from a fresh source tree before tagging.
- Prefer `reprotest` and `diffoscope` for distribution uploads. Use the
  two-build SHA-256 comparison in `docs/reproducible-builds.md` as the local
  fallback when those tools are unavailable.
