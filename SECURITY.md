# Security Policy

## Supported Versions

Until `v1.0.0` is released, only the latest `0.x` release receives security fixes.

| Version | Supported |
|---|---|
| Latest 0.x | :white_check_mark: |
| Older 0.x  | :x: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately via one of the following channels:

1. **GitHub Security Advisories** (preferred): use the
   [Report a vulnerability](https://github.com/kaplaukhd/easy-pki/security/advisories/new)
   form on the repository.
2. **Email**: kaplaukhd@gmail.com with the subject line
   `[easy-pki security] <short description>`.

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a proof-of-concept
- The affected version(s)
- Any suggested mitigation

## What to expect

- **Acknowledgement** within 72 hours.
- **Initial assessment** within 7 days.
- **Fix timeline** communicated once the issue is triaged. Critical issues are
  prioritized.
- **Coordinated disclosure**: a CVE will be requested where appropriate, and
  reporters will be credited in the release notes unless they prefer otherwise.

## Scope

In scope:

- Vulnerabilities in published `easy-pki-*` artifacts
- Cryptographic weaknesses in the library's defaults or API surface

Out of scope:

- Vulnerabilities in third-party dependencies (report upstream; we will update
  when fixes are available)
- Issues in example or documentation code not published to Maven Central
