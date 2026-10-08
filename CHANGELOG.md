# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Opt-in CA/TLS profiles:** add `CertificateProfile` and
  `PkiCertificate.rootCa()`, `intermediateCa()`, `tlsServer()` and `tlsClient()`.
  Mandatory BasicConstraints/KU/EKU defaults reject incompatible additions
  before a certificate signature is requested. Generic builders retain their
  existing behavior unless a profile is selected.
- **Issuer identity preflight:** issued profiles use `issuer(PkiIdentity)`
  to check every supplied CA's signing permission, validity containment, remaining
  path allowance and supported constraints. Intermediate path length defaults
  to zero; self-issued rollover counting and finite maximum values are handled
  explicitly. No trust or omitted-ancestor information is inferred.
- **Explicit TLS identities:** server DNS/IP SAN and client
  subject/SAN identities receive bounded ASCII/syntax checks. Client profiles
  never add serverAuth. Empty issued TLS subjects require critical SAN;
  self-signed profile subjects must be nonempty. Agreement-only subject keys are
  rejected. Profile times use whole seconds, with collapsed intervals rejected.
- **Ed25519:** add `PkiKeys.ed25519()` and certificate/signer default
  inference, including reloaded JDK `EdDSA` keys identified by named parameters.
  Ed448 remains distinct. PEM/DER, encrypted keys, PKCS#12 and PKIX are tested.
  CRL generation and test OCSP responses also infer Ed25519 after key reload.
- **Explicit RSA-PSS:** add immutable `RsaPssParameters` and JCA signer
  factories with digest, MGF1 digest and salt length. The default
  `PkiSigner.signatureParameters()` preserves existing implementations.
  Exact parameters are encoded in both certificate identifiers and used for
  signing. Default provider selection examines the key before configuring PSS;
  explicit providers never silently fall back. Unsupported combinations fail.
- **Checked signing identities:** add immutable `PkiIdentity` with
  certificate snapshots, ordered-chain link checks and fresh challenge-based
  proof of the leaf key, including opaque handles. Root omission is allowed;
  identity construction does not grant trust or replace PKIX validation.
- **Shared trust model:** add immutable `TrustBundle` with PEM/JKS/PKCS#12
  loaders, DER snapshots, deterministic deduplication and merging. Keystore
  private-key chains are ignored. Validator, path builder and Spring trust
  loading use the shared model while retaining existing entry points.
- **Self-signed SAN/EKU:** add SAN and extended key usages to the
  self-signed builder using the same extension encoder as issued certificates.
  Existing accumulation, deduplication and criticality semantics are preserved.
- **Certificate signing contract:** add `PkiSigner` with JCA adapters
  using default provider selection, a registered provider name, or an explicit
  provider instance. Both certificate builders use the contract; existing
  private-key APIs retain their defaults and named algorithm overrides.
  Self-signed certificates accept `signer(publicKey, signer)`, and issued
  certificates accept `issuer(certificate, signer)`. Explicit signer algorithms
  cannot be overridden on the builder. Signing requires no private-key export
  or global provider registration; backend failures preserve their cause.
- **JCA-compatible distinguished names:** string and fluent subject
  input now share JCA display/RDN order and correct literal escaping. Both
  certificate builders accept `X500Principal` without changing its DER.
  This corrects the previous reversal of multi-component subject names.
- **Self-issued versus self-signed:** `PkiCertInfo.isSelfIssued()`
  checks names; `isSelfSigned()` additionally verifies the signature with
  the certificate's own public key. These inspection methods do not establish trust.
- **Issuer key identifiers:** certificate and CRL AKI use issuer SKI
  when present, with a public-key hash fallback when absent. The existing
  key-identifier-only encoding and cross-signed path behavior are preserved.
- **Explicit encrypted PEM policy:** default PBES2/PBKDF2-HMAC-SHA-256
  with 600,000 iterations and AES-256-CBC; immutable `PemEncryptionOptions`
  offers a configurable positive work factor and SHA-256/SHA-512 PRFs.
  New `char[]` input/output overloads clear internal temporary copies on all
  paths without changing caller arrays. Existing String APIs and old PEM
  input remain supported; the stronger default costs more CPU.
- **Executable Spring example:** use a static single-argument
  `DynamicPropertySource`, one class-scoped PKI, explicit filter registration
  and context/file cleanup. Documentation includes the compiled MockMvc test;
  its Spring dependencies are test-scoped in the test-helper module.
- **Explicit CRL support boundary:** reject delta, scoped or indirect
  CRLs and critical CRL/entry extensions with `UNSUPPORTED_CRL`. Only complete
  direct unpartitioned candidates establish status. A later supported source
  can recover, retaining the earlier diagnostic as a warning.
- **Complete trust-only PKCS#12 round trips:** export every
  supplied certificate as a separate trusted entry. Builder aliases are
  `<alias>`, `<alias>-2`, `<alias>-3`, etc. Loading retains all trusted
  entries and provider-reported aliases in lexicographic order; the first
  alias is the primary entry. Loaded aliases survive re-export, including
  distinct aliases for repeated certificates. Identity/key bundles keep
  their existing single-key and ordered-chain behavior.
- **Bounded certificate serials:** both builders generate positive,
  nonzero serials of at most 159 bits, fitting within 20 DER INTEGER value
  octets. Explicit serials outside `1..2^159-1` are rejected immediately;
  existing certificates remain readable.
- **Bouncy Castle upgrade:** align `bcprov-jdk18on`,
  `bcpkix-jdk18on` and transitive `bcutil-jdk18on` at **1.86**, upgraded from
  1.78.1. Explicit management of `bcutil` prevents the Spring Boot BOM from
  selecting an older version. Frozen fixtures verify reading certificate
  PEM/DER, encrypted RSA/EC private-key PEM and identity PKCS#12 material
  created with 1.78.1. No new easy-pki algorithm API is introduced.
- **Accurate development and installation status:** README and
  getting-started documentation identify the unfrozen development snapshot,
  show local installation with matching Maven/Gradle coordinates, and
  distinguish artifact publication from planned versions or Git tags.
  The Java comparison now acknowledges JDK PKIX, configurable OCSP and CRL
  capabilities.
- **Complete revocation path:** check every certificate below the
  PKIX-selected trust anchor, including an omitted terminal anchor's child.
  The public supplied-chain result is preserved and anchors remain exempt.
- **OCSP freshness:** enforce `thisUpdate`, `nextUpdate` and
  `producedAt` bounds at the validation instant, including `.at(...)` and
  nonce-disabled requests. New `clockSkew(Duration)` (five minutes) and
  `maxResponseAge(Duration)` (24 hours without `nextUpdate`) settings define
  the defaults. Changed settings are applied on subsequent validations.
- **Recoverable revocation attempts:** failed or UNKNOWN OCSP
  can recover through CRL; invalid/unavailable CRL candidates can recover
  through later candidates. Recovered attempt diagnostics are available via
  `ValidationResult.getWarnings()`, separately from final `getErrors()`.
  Confirmed revocation remains fatal, as do exhausted attempts. The existing
  intermediate-with-no-source policy remains, now with an explicit warning.
- **Explicit Spring mTLS protection:** disable automatic servlet
  registration of the injectable filter. Applications enable it through
  their security chain or an explicit servlet registration.
- **Complete Spring truststore loading:** load all PKCS#12 trusted
  X.509 certificate entries in deterministic alias order. Private-key entries
  are ignored as trust sources; stores without trusted certificates fail
  configuration. Existing identity key-store loading remains unchanged.
- Version bumped to `1.0.0-SNAPSHOT`. Validation contracts are being hardened
  before the upcoming `1.0.0` release.
- **Breaking — explicit trust:** `CertValidator` requires configured
  trust anchors. A self-signed certificate or a root supplied only in
  `chain(...)` no longer establishes trust. `isTrusted()` reports anchor
  linkage; `isValid()` remains the overall acceptance decision. Spring
  validators without configured trust reject peer-supplied chains.
- **Breaking — PKIX validation:** ordered certificate paths are
  checked by JCA PKIX, including path length, issuer KeyUsage, name
  constraints, critical extensions, certificate policies and applicable
  algorithm constraints. The configured terminal anchor is excluded from
  those checks; its own expiry, self-signature and extensions are not
  validated. `getValidationPath()` still returns the subject and supplied
  chain without appending an omitted anchor. Configured CRL/OCSP checks
  run only after the path passes validation.
- **PKIX path building:** `ChainBuilder` searches an unordered
  intermediate pool for a valid path to configured trust, including
  alternative cross-signed branches. The resulting `CertChain` includes the
  selected anchor once and retains it for subsequent validation.
- README overhauled to document every module with examples, feature matrix,
  installation snippets and a side-by-side comparison against raw BouncyCastle.

### Added — documentation
- MkDocs Material documentation site under `docs/` with a home page,
  getting-started guide, per-module references (core, validation,
  spring-boot, test), a copy-paste cookbook and a side-by-side
  migration guide from raw BouncyCastle.
- `.github/workflows/docs.yml` GitHub Actions workflow that builds the
  site in strict mode and deploys it to GitHub Pages on every push to
  `main`.
- `RELEASING.md` — maintainer-only guide covering Sonatype Central
  Portal setup, GPG-signing configuration, dry-run validation and the
  step-by-step release + tag + post-release SNAPSHOT-bump workflow.

### Added — easy-pki-test (0.4.0)
- New module `easy-pki-test` (consume with `scope=test`).
- `TestPki.create().withRootCa().withIntermediateCa().build()` spins up
  a self-contained in-memory PKI hierarchy with sensible defaults
  (RSA 2048 / 10-year root / 5-year intermediate / proper CA usages).
- `TestPki.issueCert()` fluent leaf issuance: subject (string or
  `DnBuilder`), SAN with auto-detect DNS / IP / email / IPv6,
  `KeyUsage`, `ExtendedKeyUsage`, validity window, `expired()` and
  `notYetValid()` shortcuts, `rsa(int)` / `ec(Curve)` key-type helpers,
  and CA-flag support for sub-CA tests. `build()` returns just the
  certificate; `issue()` returns an `IssuedCert` record with both cert
  and the generated key pair.
- `TestPki.revoke(cert, reason)` + `TestPki.getCrl()` — internal
  revocation registry plus on-demand CRL issued by the effective CA
  signer. `TestPki.isRevoked(cert)` exposes the registry for assertions.
- `TestIssueCertBuilder.thenRevoke(reason)` — one-liner that issues a
  leaf certificate and immediately registers it as revoked.
- `TestOcspResponder` — loopback in-memory OCSP server backed by
  `TestPki`. Reports GOOD for unrevoked serials and REVOKED (with
  reason and time) for registered revocations. Nonce extensions are
  echoed back. Bound to `127.0.0.1` on a random port; close with
  try-with-resources. Started via `TestPki.startOcspResponder()`.
- `TestIssueCertBuilder.ocsp(url)` / `.crlDistributionPoint(url)` —
  convenience passthroughs so test leaves can embed the responder URL
  in their AIA / CDP extensions without dropping to the core
  `PkiCertificate.signed()` API.
- `@InjectTestPki` annotation and `EasyPkiExtension` JUnit 5 extension
  — injects a fresh `TestPki` into fields and test-method parameters
  per test method. Configurable via `withIntermediate`, `rootSubject`
  and `intermediateSubject` annotation attributes. Works on nested
  test classes and through the class hierarchy.

### Added — easy-pki-spring-boot-starter (0.3.0)
- New module `easy-pki-spring-boot-starter` targeting Spring Boot 3.3.x
  (Java 17+).
- `EasyPkiProperties` — `@ConfigurationProperties("easy-pki")` binding for
  trust store / key store / validation / monitoring, using Spring Boot's
  `Resource` abstraction and `Duration` parsing (`30m`, `12h`, `30d`).
- `ValidationMode` enum — `NONE`, `OCSP`, `CRL`, `OCSP_WITH_CRL_FALLBACK`.
- `EasyPkiAutoConfiguration` — registered via the Spring Boot 3
  `AutoConfiguration.imports` file; conditionally loads PKCS#12 trust and
  key stores into `Pkcs12Bundle` beans qualified `easyPkiTrustStore` /
  `easyPkiKeyStore`, and exposes a pre-configured `EasyPkiValidator`.
- `EasyPkiValidator` — thread-safe facade that wraps the fluent
  `CertValidator` with the configured trust anchors and revocation mode;
  offers `validate(cert[, chain...])` one-liners and `newValidator(cert)`
  for advanced per-call tuning.
- `CertificateMonitor` — periodic expiry scanner running on its own
  daemon `ScheduledExecutorService`, with `register` / `registerBundle`
  helpers, safe at-most-once event dispatch per state, and graceful
  recovery from failing listeners. Auto-registers the trust-store and
  key-store chains when those bundles are configured.
- `CertExpiringEvent` / `CertExpiredEvent` — Spring `ApplicationEvent`s
  published by the monitor; consumed via `@EventListener`.
- Monitor is auto-wired only when
  `easy-pki.monitoring.enabled=true`; the host application does not need
  `@EnableScheduling`.
- `EasyPkiHealthIndicator` — Spring Boot Actuator health contributor
  reporting `UP` / `DOWN` based on certificate expiry in the trust and
  key stores. Certificates expiring within the configured warn window are
  flagged in the details. Auto-registered as the `easyPkiHealthIndicator`
  bean only when Spring Boot Actuator is on the classpath.
- `EasyPkiClientCertFilter` — `OncePerRequestFilter` that extracts the
  client certificate chain from the standard
  `jakarta.servlet.request.X509Certificate` request attribute, validates
  it through `EasyPkiValidator`, attaches the `ValidationResult` under
  `easyPki.validationResult`, and rejects failing requests with
  `401 Unauthorized`. Supports an optional mode that passes through
  requests without a client certificate. Auto-registered when the
  Servlet API and Spring Web are on the classpath; applications opt in
  by adding the bean to their `SecurityFilterChain` before
  `X509AuthenticationFilter`.

### Added — easy-pki-validation (0.2.0)
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
- `ChainBuilder.of(cert).intermediates(pool).trustAnchors(...).build()` —
  automatic trust-path construction. Walks upward from the leaf, choosing
  candidates whose subject DN matches and whose public key verifies the
  current certificate. Accepts a JCA `KeyStore` via `.trustStore(ks)`.
  Returns a `CertChain` with `getLeaf()` / `getRoot()` / `getCertificates()`
  / `validate()` / `toValidator()`.
- `CertValidator.ocspWithCrlFallback()` — one-line convenience that
  enables OCSP with auto-fetched CRL fallback; equivalent to
  `.ocsp().crl(c -> c.autoFetch())` and further tunable via
  `.ocsp(...)` and `.crl(...)`.

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
