# easy-pki

[![Build](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/kaplaukhd/easy-pki/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17%2B-orange.svg)](https://openjdk.org/projects/jdk/17/)

**A fluent Java library for PKI operations.** BouncyCastle under the hood, an
ergonomic API on top. What used to take 40–60 lines of low-level ceremony now
fits in five readable lines — and you get validation, Spring Boot auto-config
and test helpers in the same family of modules.

> **Status:** `1.0.0-SNAPSHOT`, under active development. The API and
> validation behavior may change before a stable release; there is no API
> freeze yet. See the [migration guide](docs/migration.md) for compatibility
> guidance. The examples below use a local
> source build; a planned version or Git tag does not establish that an
> artifact is available on Maven Central.

---

## Why easy-pki?

Java already provides much of the PKI infrastructure:

- **`java.security` / JSSE** — provide PKIX path validation and building,
  OCSP/CRL checking, key stores and TLS. JDK
  [`PKIXRevocationChecker`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/cert/PKIXRevocationChecker.html)
  supports a custom OCSP responder and supplied responses; `CertStore`
  supplies CRLs. These APIs expose individual building blocks that an
  application must configure and connect.
- **BouncyCastle** — powerful but low-level. A single self-signed certificate
  requires `X500NameBuilder`, `JcaX509v3CertificateBuilder`, `ContentSigner`,
  a manual conversion back to `X509Certificate`, and forty lines of glue.

`easy-pki` combines those building blocks with Bouncy Castle through a fluent API
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

SecureRandom random = new SecureRandom();
BigInteger serial;
do {
    serial = new BigInteger(159, random);
} while (serial.signum() == 0);
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

For this development snapshot, build and install all modules in your local
Maven repository first (Java 17+, Maven 3.9+):

```bash
git clone https://github.com/kaplaukhd/easy-pki.git
cd easy-pki
mvn clean install
```

The coordinates below resolve that local `1.0.0-SNAPSHOT`. To use a published
release instead, select a version actually listed on
[Maven Central](https://central.sonatype.com/namespace/io.github.kaplaukhd)
and use the same version for all easy-pki modules.

**Maven:**

```xml
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-core</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-validation</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-tls</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>io.github.kaplaukhd</groupId>
    <artifactId>easy-pki-test</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

**Gradle:**

```kotlin
repositories {
    mavenLocal()    // the source build installed above
    mavenCentral()  // third-party dependencies
}

dependencies {
    implementation("io.github.kaplaukhd:easy-pki-core:1.0.0-SNAPSHOT")
    implementation("io.github.kaplaukhd:easy-pki-validation:1.0.0-SNAPSHOT")
    implementation("io.github.kaplaukhd:easy-pki-tls:1.0.0-SNAPSHOT")
    implementation("io.github.kaplaukhd:easy-pki-spring-boot-starter:1.0.0-SNAPSHOT")
    testImplementation("io.github.kaplaukhd:easy-pki-test:1.0.0-SNAPSHOT")
}
```

---

## Modules

| Module | Purpose |
|---|---|
| [`easy-pki-core`](easy-pki-core/) | Key generation, certificate builders, PEM/DER I/O, PKCS#12, inspection |
| [`easy-pki-validation`](easy-pki-validation/) | Chain validation, OCSP, CRL (static + HTTP auto-fetch), chain building |
| [`easy-pki-tls`](easy-pki-tls/) | JSSE adapters, explicit peer policy, atomic identity/trust rotation |
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
    .trustAnchors(root)     // root configured by the application
    .validate();

r.isValid();            // boolean
r.isTrusted();          // linkage to an explicit anchor; not the full validation result
r.getValidationPath();  // ordered: [leaf, intermediate, root]
r.getErrors();          // typed ValidationError list
r.getWarnings();        // nonfatal diagnostics from recovered revocation attempts
```

Trust anchors must come from application configuration, separately from the
peer's certificate chain. A self-signed certificate or a root passed only to
`chain(...)` does not establish trust. `CertValidator` checks the supplied
ordered chain with PKIX; use `ChainBuilder` for an unordered certificate pool.
Use `isValid()` to decide whether all configured checks passed.

The configured terminal anchor is excluded from PKIX path checks: its own
expiry, self-signature and extensions are not validated. The result's
`getValidationPath()` remains the supplied leaf and chain; an anchor omitted
from the input is not appended. See the [migration notes](docs/migration.md)
for the breaking change from earlier snapshots.

### Revocation: CRL, OCSP, and fallback

```java
// Static CRL you already have in memory
CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
    .crl(existingCrl)
    .validate();

// Auto-fetch CRLs from the certificate's CDP, with a 30-minute cache
CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
    .crl(c -> c.autoFetch()
               .cache(Duration.ofMinutes(30))
               .timeout(Duration.ofSeconds(10))
               .proxy("http://proxy.corp:3128"))
    .validate();

// OCSP with nonce, then CRL fallback on unavailability
CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
    .ocspWithCrlFallback()
    .ocsp(o -> o.timeout(Duration.ofSeconds(5)))
    .crl(c -> c.autoFetch())
    .validate();
```

Revocation checks cover every certificate below the selected trust anchor,
including when the anchor was omitted from `chain(...)`. A failed OCSP
attempt or unusable CRL candidate can recover through a valid fallback;
recovered failures appear in `getWarnings()`, while `getErrors()` contains
final failures. Confirmed revocation always rejects the path.

OCSP timestamps are checked even with nonce disabled. Defaults allow five
minutes of clock skew and, without `nextUpdate`, 24 hours of response age.
Use `.ocsp(o -> o.clockSkew(...).maxResponseAge(...))` to configure these
limits. See the [revocation policy](docs/modules/validation.md#revocation-policy)
for the existing treatment of intermediates without revocation sources.

### Automatic chain building

```java
CertChain chain = ChainBuilder.of(leaf)
    .intermediates(intermediatePool)   // Collection<X509Certificate>
    .trustStore(keyStore)              // or .trustAnchors(roots...)
    .build();                          // throws if no path exists

chain.getCertificates();  // leaf, ..., selected anchor, included once
chain.toValidator()
    .ocspWithCrlFallback()
    .validate();
```

`ChainBuilder` uses PKIX to search the pool for a valid path, including
alternative cross-signed branches. The selected trust anchor may be an
explicitly trusted intermediate. `validate()` and `toValidator()` retain
that configured trust.

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

The starter's mTLS filter has servlet auto-registration disabled. Add it to
your `SecurityFilterChain` as above to enable protection. PKCS#12 trust
loading uses every trusted certificate entry; private-key entries are
identity material and do not become trust anchors. See the
[Spring module guide](docs/modules/spring-boot.md) for explicit servlet
registration and truststore migration details.

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
| Key generation | `PkiKeys.rsa(int)` · `PkiKeys.ec(Curve)` (P-256 / P-384 / P-521) · `PkiKeys.ed25519()` |
| Self-signed certs | `PkiCertificate.selfSigned()...build()` |
| Issuer-signed certs | `PkiCertificate.signed()...build()` |
| Issuance profiles | `rootCa()` · `intermediateCa()` · `tlsServer()` · `tlsClient()` — role defaults and checks before signing |
| [PKCS#10 requests](docs/modules/core.md#certificate-signing-requests) | `PkiCsr.create()` · PEM/DER read/export · immutable `CsrRequest` inspection and signature verification |
| [CSR issuance](docs/modules/core.md#issue-under-an-explicit-ca-policy) | `PkiCsr.issue(request, policy)` — explicit subject/SAN authorization, bounded CA permission and issuer profile preflight |
| Signing backend | `PkiSigner` — JCA provider selection or external signing, without exporting private keys |
| Identity | `PkiIdentity` — signing handle, leaf and ordered chain; key possession checked without export |
| Trust | `TrustBundle` — explicit anchors from PEM/JKS/PKCS#12, immutable snapshots and merging |
| Subject DN | JCA RFC 2253/4514 order; `String`, `X500Principal` or literal `DnBuilder` values |
| Validity | `validFor(Duration)` · `validFrom(Instant)` · `validUntil(Instant)` |
| Serial | random positive nonzero, at most 159 bits / 20 DER value octets · validated `serialNumber(BigInteger)` override |
| Signature alg | automatic RSA/ECDSA SHA-256 or Ed25519; explicit RSA-PSS digest, MGF1 digest and salt via `RsaPssParameters` |
| Extensions | `BasicConstraints` · `KeyUsage` · `ExtendedKeyUsage` · SAN · CDP · AIA · SKI · AKI |
| Self-signed TLS metadata | SAN (DNS/IP) and EKU directly on the self-signed builder |
| PEM / DER I/O | `PkiCertificates` · `PkiPrivateKeys` (`char[]` passwords, configurable PBKDF2 PRF/cost, AES-256-CBC) |
| PKCS#12 | `PkiPkcs12.create()` / `.load()` — interoperable with `KeyStore` |
| Inspection | `PkiCertInfo.of(cert)` — fingerprints, `isSelfIssued()` name check, verified `isSelfSigned()` |
| CRL build | `PkiCrl.issued()...build()` with auto CRLNumber / AKI |
| CRL I/O | `PkiCrls.toPem / toDer / fromFile` (auto-detect) |
| Chain validation | `CertValidator` — PKIX validation of an ordered chain against explicit trust anchors |
| OCSP | `.ocsp(...)` — nonce, AIA-derived or explicit URL, proxy, timeout |
| CRL | `.crl(...)` — complete direct unpartitioned CRLs; static or HTTP fetch with TTL cache + proxy; unsupported forms reported explicitly |
| Fallback | `.ocspWithCrlFallback()` — OCSP first, CRL on failure |
| Chain building | `ChainBuilder.of(cert).intermediates(...).trustStore(...).build()` |
| TLS and rotation | [`PkiTls`](docs/modules/tls.md) — JSSE managers/context, SAN verification, explicit revocation policy and atomic updates |
| SSL Bundles | Opt-in named Spring bundles for Tomcat JSSE and RestClient |
| Spring Boot | `EasyPkiValidator`, `CertificateMonitor`, `EasyPkiHealthIndicator`, `EasyPkiClientCertFilter` |
| Tests | `TestPki`, `TestOcspResponder`, `@InjectTestPki`, JUnit 5 extension |

---

## Requirements

- **Java 17** or later
- **Maven 3.9+** (for building from source)
- **Bouncy Castle 1.86** (the tested version, pulled in transitively by core)
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
- **Secure defaults.** Minimum RSA 2048. Random positive, nonzero serials
  capped at 159 bits (at most 20 DER value octets, RFC 5280).
  PBKDF2-HMAC-SHA-256 (600,000 iterations) and AES-256-CBC for encrypted
  PKCS#8; configurable through `PemEncryptionOptions`. SHA-256 signatures.
- **Java-idiomatic.** `Duration`, `Instant`, typed `Optional`, immutable
  result types, fluent builders, records.
- **Interoperable.** Input and output always conform to JCA types
  (`X509Certificate`, `PrivateKey`, `KeyStore`, `X509CRL`) — you can always
  drop down to standard APIs.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Security issues — please follow [SECURITY.md](SECURITY.md).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
