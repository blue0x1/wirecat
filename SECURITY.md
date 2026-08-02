# Security Policy

Wirecat is a general-purpose stream and session utility. It does not include
persistence, stealth, autonomous operation, embedded scripting, or framework
behavior.

Use Wirecat only on systems and networks that you own, administer, or have
explicit permission to test. The project is provided for lawful administration,
debugging, research, and educational use. The author and contributors are not
responsible for misuse, damage, unauthorized access, policy violations, or
illegal activity performed with Wirecat.

## Supported Versions

The `main` branch receives security fixes until formal release branches are
created.

## Reporting

Report security issues privately to the maintainers listed for the project.
Include:

- affected commit or release,
- platform and compiler,
- command line used,
- expected and observed behavior,
- crash logs or packet captures when relevant.

## Security Defaults

- TLS client verification is enabled by default.
- TLS servers can require verified client certificates.
- TCP listeners and brokers can restrict peers with exact IP or CIDR rules.
- `--tls-insecure` is explicit and intended for local testing or controlled
  private environments.
- Listeners bind only to the address supplied by the operator.
- Process and PTY bridging require an explicit `--exec` path.
