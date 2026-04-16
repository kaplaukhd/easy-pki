# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — easy-pki-validation (0.2.0 in progress)
- New module `easy-pki-validation` depending on `easy-pki-core`.
- `CertValidator` — fluent chain validator: `CertValidator.of(cert).chain(...).trustAnchors(...).at(instant).validate()`.
- `ValidationResult` — immutable result with `isValid / isExpired / isNotYetValid / isTrusted / isRevoked / getRevokeReason / getRevokeTime / getValidationPath / getErrors`.
- `ValidationError` record with a code enum (`EXPIRED`, `NOT_YET_VALID`, `ISSUER_MISMATCH`, `BROKEN_SIGNATURE`, `NOT_A_CA`, `UNTRUSTED_ROOT`, `INCOMPLETE_CHAIN`, `REVOKED`, `REVOCATION_UNKNOWN`, `OCSP_UNAVAILABLE`, `CRL_UNAVAILABLE`).
- `RevocationReason` enum with RFC 5280 §5.3.1 CRLReason codes and round-trip `fromCode(int)`.
- `PkiCrl.issued()` + `CrlBuilder` — fluent CRL issuance with automatic
  AuthorityKeyIdentifier and CRLNumber, RSA/EC signing, and per-entry reason
  codes. `revoke(X509Certificate, RevocationReason)` and
  `revoke(BigInteger, RevocationReason, Instant)` overloads.
- `PkiCrls` — PEM and DER I/O for X.509 CRLs, file auto-detect.
- `CertValidator.crl(X509CRL...)` — opt-in CRL-based revocation checking.
  For each non-anchor cert in the path the validator finds a matching CRL
  by issuer DN, verifies the CRL's signature against the issuer's public
  key, enforces `thisUpdate`/`nextUpdate` freshness, and reports
  `REVOKED`, `REVOCATION_UNKNOWN`, or `CRL_UNAVAILABLE` accordingly.
- `CrlConfig` + `CertValidator.crl(Consumer<CrlConfig>)` — full CRL
  configuration with HTTP auto-fetch from the certificate's CRL
  Distribution Points, in-memory TTL cache, per-request HTTP timeout and
  optional proxy. Transport uses the JDK's built-in `java.net.http.HttpClient`.
- `OcspConfig` + `CertValidator.ocsp()` / `CertValidator.ocsp(Consumer<OcspConfig>)`
  — OCSP revocation checking with nonce support, per-request timeout and
  optional proxy. The responder URL is taken from each certificate's
  Authority Information Access extension or overridden explicitly.
- When both OCSP and CRL are configured, OCSP is consulted first;
  CRL is used as a fallback on OCSP unavailability.
- Revocation policy: the subject certificate must be checkable (else
  `REVOCATION_UNKNOWN`); intermediate certificates silently pass when no
  revocation data is available, matching common browser behaviour.

### Added — easy-pki-core
- Initial project skeleton: Maven multi-module layout, `easy-pki-core` module.
- Apache License 2.0, NOTICE, CODE_OF_CONDUCT, SECURITY, CONTRIBUTING.
- GitHub Actions CI pipeline (build + test on Java 17 and 21).
- `PkiKeys.rsa(int)` — RSA key pair generation (minimum 2048 bits, exponent F4).
- `PkiKeys.ec(Curve)` — elliptic-curve key pair generation.
- `Curve` enum with `P_256`, `P_384`, `P_521`.
- `PkiCertificate.selfSigned()` — fluent builder for self-signed X.509 certificates.
  Supports subject via RFC 4514 string or `DnBuilder` sub-builder; RSA and EC
  keys; explicit or relative validity windows; `BasicConstraints` (CA + path
  length) and `KeyUsage` extensions; automatic `SubjectKeyIdentifier` and
  `AuthorityKeyIdentifier`; random 20-byte RFC 5280 §4.1.2.2 serial by default.
- `DnBuilder` — fluent builder for X.500 Distinguished Names.
- `KeyUsage` enum covering the nine standard X.509 key-usage bits.
- `PkiCertificate.signed()` — fluent builder for certificates issued by a CA.
  Accepts issuer certificate + private key; supports SAN (DNS / IP / e-mail /
  URI) via `SanBuilder`, Extended Key Usage, CRL Distribution Points, and AIA
  OCSP URLs. Authority Key Identifier is derived from the issuer's public key.
- `ExtendedKeyUsage` enum — `TLS_SERVER`, `TLS_CLIENT`, `CODE_SIGNING`,
  `EMAIL_PROTECTION`, `TIME_STAMPING`, `OCSP_SIGNING`.
- `SanBuilder` — fluent builder for Subject Alternative Name entries.
- `PkiCertificates` — PEM and DER read/write for X.509 certificates, including
  multi-certificate PEM chains.
- `PkiPrivateKeys` — PEM read/write for private keys. Reads unencrypted and
  encrypted PKCS#8, traditional OpenSSL PKCS#1 RSA and EC formats. Writes
  modern PKCS#8 (PBES2 + AES-256-CBC when password is given).
- `PkiPkcs12` + `Pkcs12Builder` + `Pkcs12Bundle` — PKCS#12 keystore creation
  and loading. Output interoperates with standard JCA `KeyStore` API.
- `PkiCertInfo` — ergonomic read-only view over `X509Certificate`: subject,
  issuer, serial, validity, self-signed check, expiry helpers (`isExpired`,
  `isExpiringWithin`, `isNotYetValid`), CA / path-length, key usages,
  extended key usages, SAN entries, OCSP / CRL URLs, public-key algorithm and
  size, SHA-1/256/384/512 fingerprint (colon-separated hex).
- `HashAlgorithm` enum — `SHA1`, `SHA256`, `SHA384`, `SHA512`.
- `SubjectAlternativeName` record — typed SAN entry (`DNS`, `IP_ADDRESS`,
  `EMAIL`, `URI`, `DIRECTORY_NAME`, `OTHER`).

[Unreleased]: https://github.com/kaplaukhd/easy-pki/compare/HEAD...HEAD
