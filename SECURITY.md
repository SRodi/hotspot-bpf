# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | ✅                 |

## Reporting a Vulnerability

If you discover a security vulnerability in hotspot-bpf, please report it
responsibly via [GitHub Security Advisories](https://github.com/SRodi/hotspot-bpf/security/advisories/new).

**Do not open a public issue for security vulnerabilities.**

You can expect an initial response within 72 hours. We will work with you to
understand the issue and coordinate a fix before any public disclosure.

## Security Practices

- Dependencies are monitored by [Dependabot](https://github.com/dependabot)
  and scanned with [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
  (keyless / Sigstore) and include an SBOM
- The project is evaluated by [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/SRodi/hotspot-bpf)
