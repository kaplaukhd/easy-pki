# Contributing to easy-pki

Thank you for your interest in contributing! This document explains how to get started.

## Ground rules

- Be respectful. This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
- Security issues must **not** be reported through public issues. See [SECURITY.md](SECURITY.md).
- By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Getting started

### Prerequisites

- JDK 17 or later
- Maven 3.9 or later
- Git

### Build

```bash
git clone https://github.com/kaplaukhd/easy-pki.git
cd easy-pki
mvn clean verify
```

`mvn verify` runs the full test suite and static analysis. All checks must pass before a pull request is accepted.

## Workflow

1. **Open an issue first** for any non-trivial change. This avoids wasted work on an approach the maintainers won't accept.
2. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/short-description
   ```
3. Make your changes. Keep commits focused and atomic.
4. Add or update tests. New functionality without tests will not be merged.
5. Ensure `mvn verify` passes locally.
6. Open a pull request. Describe the problem, the solution, and any tradeoffs.

## Code style

- Java 17 syntax. No preview features.
- Public API must be documented with Javadoc.
- Prefer clarity over cleverness. The whole point of this library is readability.
- Match existing style. When in doubt, follow the surrounding code.

## Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) style:

```
feat(core): add Keys.ec(Curve) for elliptic curve key generation
fix(core): handle null subject in CertInfo.getSubject()
docs: document PKCS#12 password requirements
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `ci`, `chore`.

## Pull request checklist

- [ ] Tests cover the change
- [ ] `mvn verify` passes
- [ ] Public API changes have Javadoc
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Commit messages follow Conventional Commits

## Questions

Use [GitHub Discussions](https://github.com/kaplaukhd/easy-pki/discussions) for design questions and general Q&A.
