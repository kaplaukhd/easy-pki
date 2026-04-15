# easy-pki

[![Build](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17%2B-orange.svg)](https://openjdk.org/projects/jdk/17/)

**A fluent Java library for PKI operations.** BouncyCastle under the hood, an
ergonomic API on top. What used to take 40–60 lines of low-level ceremony now
fits in five readable lines.

> **Status:** active development. The first release (`v0.1.0`) is feature-
> complete in the core module but the public API is not yet frozen — expect
> minor breaking changes until `v1.0.0`.

---

## Why easy-pki?

Working with X.509 in Java today means choosing between:

- **`java.security` / JSSE** — limited, no support for custom OCSP/CRL
  endpoints, awkward for anything beyond textbook TLS.
- **BouncyCastle** — powerful but low-level. A single self-signed certificate
  requires `X500NameBuilder`, `JcaX509v3CertificateBuilder`, `ContentSigner`,
  a manual conversion back to `X509Certificate`, and forty lines of glue.

`easy-pki` is the missing middle layer — a fluent, discoverable API designed
for everyday tasks: spinning up a CA, issuing a leaf cert with SANs, inspecting
an expiring certificate, loading a PKCS#12 bundle.

### Side-by-side comparison

<table>
<tr>
<th>Raw BouncyCastle</th>
<th>easy-pki</th>
</tr>
<tr>
<td valign="top">

```java
KeyPairGenerator kpg = KeyPairGenerator
    .getInstance("RSA", "BC");
kpg.initialize(new RSAKeyGenParameterSpec(
    2048, RSAKeyGenParameterSpec.F4));
KeyPair keys = kpg.generateKeyPair();

X500Name subject = new X500NameBuilder()
    .addRDN(BCStyle.CN, "example.com")
    .addRDN(BCStyle.O, "MyOrg")
    .build();

BigInteger serial = BigInteger.valueOf(
    System.currentTimeMillis());
Date notBefore = new Date();
Date notAfter = Date.from(Instant.now()
    .plus(365, ChronoUnit.DAYS));

X509v3CertificateBuilder builder =
    new JcaX509v3CertificateBuilder(
        subject, serial, notBefore,
        notAfter, subject, keys.getPublic());

builder.addExtension(
    Extension.basicConstraints, true,
    new BasicConstraints(true));

ContentSigner signer =
    new JcaContentSignerBuilder("SHA256withRSA")
        .build(keys.getPrivate());
X509CertificateHolder holder =
    builder.build(signer);

X509Certificate cert = new
    JcaX509CertificateConverter()
    .setProvider("BC")
    .getCertificate(holder);
```

</td>
<td valign="top">

```java
KeyPair keys = PkiKeys.rsa(2048);

X509Certificate cert = PkiCertificate.selfSigned()
    .subject("CN=example.com, O=MyOrg")
    .keyPair(keys)
    .validFor(Duration.ofDays(365))
    .isCA(true)
    .build();
```

</td>
</tr>
</table>

---

## Installation

`easy-pki` will be published to Maven Central. Until the first release, build
locally (see [Building from source](#building-from-source)).

**Maven:**

```xml
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-core</artifactId>
    <version>0.1.0</version>
</dependency>
```

**Gradle:**

```kotlin
implementation("io.github.kaplaukhd:easy-pki-core:0.1.0")
```

---

## Quick start

### Generate keys

```java
KeyPair rsa = PkiKeys.rsa(2048);
KeyPair ec  = PkiKeys.ec(Curve.P_256);
```

### A three-cert chain: root → intermediate → leaf

```java
// Root CA
KeyPair rootKeys = PkiKeys.rsa(4096);
X509Certificate root = PkiCertificate.selfSigned()
    .subject("CN=Acme Root CA, O=Acme, C=US")
    .keyPair(rootKeys)
    .validFor(Duration.ofDays(3650))
    .pathLength(1)
    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
    .build();

// Intermediate CA
KeyPair intermediateKeys = PkiKeys.rsa(2048);
X509Certificate intermediate = PkiCertificate.signed()
    .subject("CN=Acme Issuing CA, O=Acme")
    .publicKey(intermediateKeys.getPublic())
    .issuer(root, rootKeys.getPrivate())
    .validFor(Duration.ofDays(1825))
    .pathLength(0)
    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
    .build();

// End-entity TLS certificate
KeyPair serverKeys = PkiKeys.ec(Curve.P_256);
X509Certificate server = PkiCertificate.signed()
    .subject("CN=api.example.com")
    .publicKey(serverKeys.getPublic())
    .issuer(intermediate, intermediateKeys.getPrivate())
    .validFor(Duration.ofDays(365))
    .san(s -> s.dns("api.example.com")
               .dns("*.api.example.com")
               .ip("10.0.0.1"))
    .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
    .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT)
    .crlDistributionPoint("http://crl.example.org/ca.crl")
    .ocsp("http://ocsp.example.org")
    .build();
```

### Read and write files

```java
// Certificates
String pem = PkiCertificates.toPem(server);
PkiCertificates.toFile(List.of(server, intermediate, root), Path.of("chain.pem"));
X509Certificate back = PkiCertificates.fromPem(pem);
List<X509Certificate> chain = PkiCertificates.allFromFile(Path.of("chain.pem"));

// Private keys (PKCS#8, AES-256-CBC when a password is provided)
String keyPem    = PkiPrivateKeys.toPem(serverKeys.getPrivate());
String encrypted = PkiPrivateKeys.toPem(serverKeys.getPrivate(), "changeit");
PrivateKey key   = PkiPrivateKeys.fromPem(encrypted, "changeit");

// PKCS#12 bundles
PkiPkcs12.create()
    .certificate(server)
    .privateKey(serverKeys.getPrivate())
    .chain(intermediate, root)
    .alias("server")
    .password("changeit")
    .build()
    .saveTo(Path.of("keystore.p12"));

Pkcs12Bundle loaded = PkiPkcs12.load(Path.of("keystore.p12"), "changeit");
```

### Inspect a certificate

```java
PkiCertInfo info = PkiCertInfo.of(server);

info.getSubject();                           // "CN=api.example.com"
info.getIssuer();                            // "CN=Acme Issuing CA, O=Acme"
info.isExpired();                            // false
info.isExpiringWithin(Duration.ofDays(30));  // monitoring-friendly
info.getSans();                              // typed entries (DNS / IP / …)
info.getKeyUsages();                         // Set<KeyUsage>
info.getExtendedKeyUsages();                 // Set<ExtendedKeyUsage>
info.getOcspUrls();                          // List<String>
info.getCrlUrls();                           // List<String>
info.getFingerprint(HashAlgorithm.SHA256);   // "AB:CD:EF:..."
info.getPublicKeyAlgorithm();                // "EC"
info.getPublicKeySize();                     // 256
```

---

## Feature matrix (v0.1.0 core)

| Area | API |
|---|---|
| Key generation | `PkiKeys.rsa(int)` · `PkiKeys.ec(Curve)` |
| Self-signed certs | `PkiCertificate.selfSigned()...build()` |
| Issuer-signed certs | `PkiCertificate.signed()...build()` |
| Subject DN | RFC 4514 string *or* `DnBuilder` (`cn/o/ou/c/l/st/email/...`) |
| Validity | `validFor(Duration)` · `validFrom(Instant)` · `validUntil(Instant)` |
| Serial | random 20-byte (RFC 5280 §4.1.2.2) · `serialNumber(BigInteger)` override |
| Signature alg | auto from issuer key (SHA-256 + RSA / ECDSA) · override |
| Extensions | `BasicConstraints` · `KeyUsage` · `ExtendedKeyUsage` · SAN · CDP · AIA (OCSP) · SKI · AKI |
| PEM / DER I/O | `PkiCertificates` · `PkiPrivateKeys` (incl. encrypted PKCS#8) |
| PKCS#12 | `PkiPkcs12.create()` · `PkiPkcs12.load()` · interop with `KeyStore.getInstance("PKCS12")` |
| Inspection | `PkiCertInfo.of(cert)` — 20+ accessors |
| Fingerprints | SHA-1 / SHA-256 / SHA-384 / SHA-512, colon-separated hex |

---

## Modules

| Module | Status | Purpose |
|---|---|---|
| [`easy-pki-core`](easy-pki-core/) | **stable API surface as of 0.1.0** | Keys, certificate builders, I/O, PKCS#12, inspection |
| `easy-pki-validation` | planned (0.2.0) | OCSP, CRL, chain building, validation results |
| `easy-pki-spring-boot-starter` | planned (0.3.0) | Auto-configuration, monitoring, mTLS, Actuator |
| `easy-pki-test` | planned (0.4.0) | In-memory CA hierarchy and OCSP responder for tests |

---

## Requirements

- **Java 17** or later
- **Maven 3.9+** (for building from source)
- **BouncyCastle 1.78+** (pulled in transitively)

---

## Building from source

```bash
git clone https://github.com/kaplaukhd/easy-pki.git
cd easy-pki
mvn clean verify
```

`mvn verify` runs the full test suite and JaCoCo coverage report. All checks
must pass before a pull request is accepted.

---

## Design principles

- **One way to do it.** Each task has a single obvious entry point.
- **No magic global state.** BouncyCastle is never registered in the JCA
  provider list — the host application's security configuration stays untouched.
- **Fail loudly at the boundary.** Malformed input and missing required fields
  throw clear, actionable exceptions — not cryptic wrapped `GeneralSecurityException`s.
- **Secure defaults.** Minimum RSA 2048. Random 20-byte serial numbers per
  RFC 5280. AES-256-CBC for encrypted PKCS#8.
- **Java-idiomatic.** `Duration`, `Instant`, `Optional` where appropriate,
  immutable result types, fluent builders.

---

## Roadmap

See [easy-pki-roadmap.md](easy-pki-roadmap.md) for the full design and release
plan.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Security issues — please follow [SECURITY.md](SECURITY.md).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
