# easy-pki

[![Build](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17%2B-orange.svg)](https://openjdk.org/projects/jdk/17/)

**A fluent Java library for PKI operations.** BouncyCastle under the hood, an
ergonomic API on top. What used to take 40–60 lines of low-level ceremony now
fits in five readable lines — and you get validation, Spring Boot auto-config
and test helpers in the same family of modules.

> **Status:** `1.0.0-SNAPSHOT` in progress. All four modules are
> feature-complete and stable; the public API is considered locked for
> `1.0.0`. Final publication to Maven Central happens with the first
> tagged release.

---

## Why easy-pki?

Working with X.509 in Java today means choosing between:

- **`java.security` / JSSE** — limited, no support for custom OCSP/CRL
  endpoints, awkward for anything beyond textbook TLS.
- **BouncyCastle** — powerful but low-level. A single self-signed certificate
  requires `X500NameBuilder`, `JcaX509v3CertificateBuilder`, `ContentSigner`,
  a manual conversion back to `X509Certificate`, and forty lines of glue.

`easy-pki` is the missing middle layer — a fluent, discoverable API designed
for everyday tasks: spinning up a CA, issuing a leaf cert with SANs,
validating a chain with OCSP, loading a PKCS#12 bundle, monitoring expiry,
writing a mTLS test.

### Side-by-side: self-signed root CA

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

`easy-pki` is a Maven multi-module project. Depend on the parts you need.

**Maven:**

```xml
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-core</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-validation</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-test</artifactId>
    <version>1.0.0</version>
    <scope>test</scope>
</dependency>
```

**Gradle:**

```kotlin
implementation("io.github.kaplaukhd:easy-pki-core:1.0.0")
implementation("io.github.kaplaukhd:easy-pki-validation:1.0.0")
implementation("io.github.kaplaukhd:easy-pki-spring-boot-starter:1.0.0")
testImplementation("io.github.kaplaukhd:easy-pki-test:1.0.0")
```

---

## Modules

| Module | Purpose |
|---|---|
| [`easy-pki-core`](easy-pki-core/) | Key generation, certificate builders, PEM/DER I/O, PKCS#12, inspection |
| [`easy-pki-validation`](easy-pki-validation/) | Chain validation, OCSP, CRL (static + HTTP auto-fetch), chain building |
| [`easy-pki-spring-boot-starter`](easy-pki-spring-boot-starter/) | Auto-configuration, expiry monitor, Actuator health, mTLS filter |
| [`easy-pki-test`](easy-pki-test/) | In-memory CA hierarchy, OCSP responder, JUnit 5 extension |

---

## Quick start: a three-cert chain

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

---

## I/O: PEM, DER, PKCS#12

```java
// Certificates
String pem = PkiCertificates.toPem(server);
PkiCertificates.toFile(List.of(server, intermediate, root), Path.of("chain.pem"));
X509Certificate back    = PkiCertificates.fromPem(pem);
List<X509Certificate> c = PkiCertificates.allFromFile(Path.of("chain.pem"));

// Private keys (PKCS#8; AES-256-CBC when a password is provided)
String keyPem    = PkiPrivateKeys.toPem(serverKeys.getPrivate());
String encrypted = PkiPrivateKeys.toPem(serverKeys.getPrivate(), "changeit");
PrivateKey key   = PkiPrivateKeys.fromPem(encrypted, "changeit");

// PKCS#12 bundles — interoperable with standard KeyStore.getInstance("PKCS12")
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

---

## Inspection

```java
PkiCertInfo info = PkiCertInfo.of(server);

info.getSubject();                           // "CN=api.example.com"
info.getIssuer();                            // "CN=Acme Issuing CA, O=Acme"
info.isExpired();                            // false
info.isExpiringWithin(Duration.ofDays(30));  // monitoring hook
info.getSans();                              // typed List<SubjectAlternativeName>
info.getKeyUsages();                         // Set<KeyUsage>
info.getExtendedKeyUsages();                 // Set<ExtendedKeyUsage>
info.getOcspUrls();                          // List<String> from AIA extension
info.getCrlUrls();                           // List<String> from CDP extension
info.getFingerprint(HashAlgorithm.SHA256);   // "AB:CD:EF:..."
info.getPublicKeyAlgorithm();                // "EC"
info.getPublicKeySize();                     // 256
```

---

## Validation (`easy-pki-validation`)

### Chain-only

```java
ValidationResult r = CertValidator.of(leaf)
    .chain(intermediate, root)
    .validate();

r.isValid();            // boolean
r.getValidationPath();  // ordered: [leaf, intermediate, root]
r.getErrors();          // typed ValidationError list
```

### Revocation: CRL, OCSP, and fallback

```java
// Static CRL you already have in memory
CertValidator.of(leaf).chain(intermediate, root)
    .crl(existingCrl)
    .validate();

// Auto-fetch CRLs from the certificate's CDP, with a 30-minute cache
CertValidator.of(leaf).chain(intermediate, root)
    .crl(c -> c.autoFetch()
               .cache(Duration.ofMinutes(30))
               .timeout(Duration.ofSeconds(10))
               .proxy("http://proxy.corp:3128"))
    .validate();

// OCSP with nonce, then CRL fallback on unavailability
CertValidator.of(leaf).chain(intermediate, root)
    .ocspWithCrlFallback()
    .ocsp(o -> o.timeout(Duration.ofSeconds(5)))
    .crl(c -> c.autoFetch())
    .validate();
```

### Automatic chain building

```java
CertChain chain = ChainBuilder.of(leaf)
    .intermediates(intermediatePool)   // Collection<X509Certificate>
    .trustStore(keyStore)              // or .trustAnchors(roots...)
    .build();                          // throws if no path exists

chain.getCertificates();  // leaf, ..., root
chain.toValidator()
    .ocspWithCrlFallback()
    .validate();
```

---

## Spring Boot (`easy-pki-spring-boot-starter`)

Drop the starter into `pom.xml`, add a bit of YAML, and you get a ready
`EasyPkiValidator`, certificate-expiry monitoring, an Actuator health
indicator, and a mTLS filter for Spring Security.

```yaml
easy-pki:
  trust-store:
    path: classpath:truststore.p12
    password: changeit
  key-store:
    path: /etc/ssl/keystore.p12
    password: ${KEYSTORE_PASSWORD}
  validation:
    mode: OCSP_WITH_CRL_FALLBACK   # NONE | OCSP | CRL | OCSP_WITH_CRL_FALLBACK
    ocsp-timeout: 5s
    crl-cache-ttl: 30m
    http-timeout: 10s
    proxy: http://proxy.corp:3128
  monitoring:
    enabled: true
    warn-before: 30d
    check-interval: 12h

management:
  endpoints:
    web:
      exposure:
        include: health
```

```java
@Service
public class TlsService {
    private final EasyPkiValidator validator;

    public TlsService(EasyPkiValidator validator) {
        this.validator = validator;
    }

    public void check(X509Certificate clientCert, X509Certificate intermediate) {
        ValidationResult r = validator.validate(clientCert, intermediate);
        if (!r.isValid()) throw new SecurityException(r.getErrors().toString());
    }
}

@Component
public class ExpiryAlerts {
    @EventListener
    public void onExpiring(CertExpiringEvent e) {
        log.warn("{} expires in {} days", e.getAlias(), e.getDaysLeft());
    }
    @EventListener
    public void onExpired(CertExpiredEvent e) {
        alertService.page("Certificate " + e.getAlias() + " has expired");
    }
}

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
                                    EasyPkiClientCertFilter easyPki) throws Exception {
        return http
            .x509(x -> x.subjectPrincipalRegex("CN=(.*?)(?:,|$)"))
            .addFilterBefore(easyPki, X509AuthenticationFilter.class)
            .build();
    }
}
```

The `/actuator/health` endpoint gains a `pki` component with per-certificate
details (subject, `notAfter`, `daysLeft`, `OK`/`EXPIRING`/`EXPIRED`).

---

## Testing (`easy-pki-test`)

A self-contained PKI for unit and integration tests, issued in three lines.

```java
@ExtendWith(EasyPkiExtension.class)
class MyServiceTest {

    @InjectTestPki
    TestPki pki;

    @Test
    void validCertIsAccepted() {
        X509Certificate cert = pki.issueCert()
            .subject("CN=client")
            .san("client.example.org", "10.0.0.1")
            .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
            .build();

        assertThat(service.accept(cert)).isTrue();
    }

    @Test
    void expiredCertIsRejected() {
        X509Certificate cert = pki.issueCert()
            .subject("CN=old")
            .expired()                      // notBefore = -60d, notAfter = -1d
            .build();

        assertThat(service.accept(cert)).isFalse();
    }

    @Test
    void revokedCertIsRejected() throws Exception {
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {
            X509Certificate cert = pki.issueCert()
                .subject("CN=bad")
                .ocsp(ocsp.getUrl())
                .thenRevoke(RevocationReason.KEY_COMPROMISE);

            assertThat(service.accept(cert)).isFalse();
        }
    }
}
```

---

## Feature matrix

| Area | API |
|---|---|
| Key generation | `PkiKeys.rsa(int)` · `PkiKeys.ec(Curve)` (P-256 / P-384 / P-521) |
| Self-signed certs | `PkiCertificate.selfSigned()...build()` |
| Issuer-signed certs | `PkiCertificate.signed()...build()` |
| Subject DN | RFC 4514 string *or* `DnBuilder` (`cn/o/ou/c/l/st/email/...`) |
| Validity | `validFor(Duration)` · `validFrom(Instant)` · `validUntil(Instant)` |
| Serial | random 20-byte (RFC 5280) · `serialNumber(BigInteger)` override |
| Signature alg | auto (SHA-256 + RSA / ECDSA) · override |
| Extensions | `BasicConstraints` · `KeyUsage` · `ExtendedKeyUsage` · SAN · CDP · AIA · SKI · AKI |
| PEM / DER I/O | `PkiCertificates` · `PkiPrivateKeys` (incl. encrypted PKCS#8 AES-256-CBC) |
| PKCS#12 | `PkiPkcs12.create()` / `.load()` — interoperable with `KeyStore` |
| Inspection | `PkiCertInfo.of(cert)` — 20+ accessors including fingerprints |
| CRL build | `PkiCrl.issued()...build()` with auto CRLNumber / AKI |
| CRL I/O | `PkiCrls.toPem / toDer / fromFile` (auto-detect) |
| Chain validation | `CertValidator` — signatures, DN continuity, CA flag, validity, trust anchors |
| OCSP | `.ocsp(...)` — nonce, AIA-derived or explicit URL, proxy, timeout |
| CRL | `.crl(...)` — static list **or** HTTP auto-fetch with TTL cache + proxy |
| Fallback | `.ocspWithCrlFallback()` — OCSP first, CRL on failure |
| Chain building | `ChainBuilder.of(cert).intermediates(...).trustStore(...).build()` |
| Spring Boot | `EasyPkiValidator`, `CertificateMonitor`, `EasyPkiHealthIndicator`, `EasyPkiClientCertFilter` |
| Tests | `TestPki`, `TestOcspResponder`, `@InjectTestPki`, JUnit 5 extension |

---

## Requirements

- **Java 17** or later
- **Maven 3.9+** (for building from source)
- **BouncyCastle 1.78+** (pulled in transitively by core)
- **Spring Boot 3.3+** (only for the starter)

The library **never registers BouncyCastle globally**. Your application's JCA
provider configuration stays untouched.

---

## Building from source

```bash
git clone https://github.com/kaplaukhd/easy-pki.git
cd easy-pki
mvn clean verify
```

`mvn verify` runs the full test suite, static analysis, and the JaCoCo
coverage report. All checks must pass before a pull request is accepted.

---

## Design principles

- **One obvious way.** Each task has a single discoverable entry point.
- **No magic global state.** BouncyCastle is never registered in the JCA
  provider list — the host application's security configuration stays
  untouched.
- **Fail loudly at the boundary.** Malformed input and missing required fields
  throw clear, actionable exceptions — never wrapped `GeneralSecurityException`
  stack traces.
- **Secure defaults.** Minimum RSA 2048. Random 20-byte serials (RFC 5280).
  AES-256-CBC for encrypted PKCS#8. SHA-256 signatures.
- **Java-idiomatic.** `Duration`, `Instant`, typed `Optional`, immutable
  result types, fluent builders, records.
- **Interoperable.** Input and output always conform to JCA types
  (`X509Certificate`, `PrivateKey`, `KeyStore`, `X509CRL`) — you can always
  drop down to standard APIs.

---

## Roadmap

See [easy-pki-roadmap.md](easy-pki-roadmap.md) for the full design notes.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Security issues — please follow [SECURITY.md](SECURITY.md).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
