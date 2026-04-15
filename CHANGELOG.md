# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
