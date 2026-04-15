# easy-pki — Project Description & Roadmap

> **Tagline:** BouncyCastle is powerful, but painful. `easy-pki` is a fluent Java API that makes working with certificates as simple as working with dates in Joda-Time.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Target Audience](#target-audience)
3. [Project Structure](#project-structure)
4. [Module 1 — easy-pki-core](#module-1--easy-pki-core)
5. [Module 2 — easy-pki-validation](#module-2--easy-pki-validation)
6. [Module 3 — easy-pki-spring-boot-starter](#module-3--easy-pki-spring-boot-starter)
7. [Module 4 — easy-pki-test](#module-4--easy-pki-test)
8. [Technical Stack](#technical-stack)
9. [Roadmap](#roadmap)
10. [Publishing & Promotion](#publishing--promotion)

---

## Problem Statement

Working with PKI in Java today requires choosing between two bad options:

- **Standard Java (`java.security`, `JSSE`)** — inflexible, limited, poor support for custom OCSP/CRL endpoints and extensions.
- **BouncyCastle** — powerful but low-level. Generating a single certificate requires 40–60 lines of boilerplate with `X500NameBuilder`, `JcaX509v3CertificateBuilder`, `ContentSigner`, and other unfriendly APIs.

There is no modern, ergonomic Java library that provides a fluent, developer-friendly API for common PKI operations.

**Before easy-pki (BouncyCastle raw):**
```java
// ~50 lines just to generate a self-signed certificate
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
KeyPair keyPair = kpg.generateKeyPair();
X500Name subject = new X500NameBuilder()
    .addRDN(BCStyle.CN, "example.com")
    .addRDN(BCStyle.O, "MyOrg")
    .build();
BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
Date notBefore = new Date();
Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
    subject, serial, notBefore, notAfter, subject,
    keyPair.getPublic()
);
// ... add extensions, sign, convert ...
```

**After easy-pki:**
```java
KeyPair keys = Keys.rsa(2048);
X509Certificate cert = Certificate.selfSigned()
    .subject("CN=example.com, O=MyOrg")
    .keyPair(keys)
    .validFor(Duration.ofDays(365))
    .build();
```

---

## Target Audience

- Java/Kotlin developers building applications with mTLS, client certificate authentication
- Teams running internal/corporate PKI infrastructure
- Developers working with digital signatures, document signing (PKCS#7/CMS)
- Anyone using BouncyCastle who wants a cleaner API on top
- Spring Boot teams needing certificate lifecycle management

---

## Project Structure

```
easy-pki/
├── easy-pki-core/                  # Core API — no dependencies except BouncyCastle
├── easy-pki-validation/            # OCSP/CRL certificate validation
├── easy-pki-spring-boot-starter/   # Spring Boot auto-configuration
├── easy-pki-test/                  # Test helpers — generate PKI infrastructure in tests
├── examples/                       # Usage examples for each module
└── docs/                           # MkDocs documentation (published to GitHub Pages)
```

Each module is an independent Maven artifact. Users can include only what they need.

---

## Module 1 — `easy-pki-core`

**Maven artifact:** `io.github.yourname:easy-pki-core`

The foundation of the library. No Spring, no optional dependencies — just BouncyCastle under the hood.

### 1.1 Key Generation

```java
KeyPair rsa2048  = Keys.rsa(2048);
KeyPair rsa4096  = Keys.rsa(4096);
KeyPair ecP256   = Keys.ec(Curve.P_256);
KeyPair ecP384   = Keys.ec(Curve.P_384);
```

### 1.2 Certificate Generation — Fluent Builder

**Self-signed (Root CA):**
```java
X509Certificate rootCa = Certificate.selfSigned()
    .subject("CN=My Root CA, O=Corp, C=RU")
    .keyPair(rootKeyPair)
    .validFor(Duration.ofDays(3650))
    .isCA(true)
    .pathLength(1)
    .build();
```

**Intermediate CA:**
```java
X509Certificate intermediateCa = Certificate.signed()
    .subject("CN=Issuing CA, O=Corp")
    .issuer(rootCa, rootPrivateKey)
    .publicKey(intermediateKeyPair.getPublic())
    .validFor(Duration.ofDays(1825))
    .isCA(true)
    .pathLength(0)
    .build();
```

**TLS End-entity certificate:**
```java
X509Certificate tlsCert = Certificate.signed()
    .subject("CN=api.example.com")
    .issuer(intermediateCa, intermediatePrivateKey)
    .publicKey(serverKeyPair.getPublic())
    .validFor(Duration.ofDays(365))
    .san()
        .dns("api.example.com")
        .dns("*.api.example.com")
        .ip("192.168.1.1")
        .done()
    .keyUsage(DIGITAL_SIGNATURE, KEY_ENCIPHERMENT)
    .extendedKeyUsage(TLS_SERVER, TLS_CLIENT)
    .crlDistributionPoint("http://crl.corp.internal/root.crl")
    .ocsp("http://ocsp.corp.internal")
    .build();
```

### 1.3 Reading & Writing Certificates

```java
// Reading
X509Certificate cert = Certificates.fromPem(pemString);
X509Certificate cert = Certificates.fromDer(bytes);
X509Certificate cert = Certificates.fromFile(path);

PrivateKey key = PrivateKeys.fromPem(pemString);
PrivateKey key = PrivateKeys.fromPem(pemString, "password"); // encrypted PKCS#8

// Writing
String pem  = Certificates.toPem(cert);
byte[] der  = Certificates.toDer(cert);
Certificates.toFile(cert, path);
```

### 1.4 PKCS#12 Keystores

```java
// Create
Pkcs12Bundle bundle = Pkcs12.create()
    .certificate(cert)
    .privateKey(privateKey)
    .chain(intermediate, root)
    .password("secret")
    .build();

bundle.saveTo(Path.of("keystore.p12"));

// Load
Pkcs12Bundle loaded = Pkcs12.load(Path.of("keystore.p12"), "secret");
loaded.getCertificate();
loaded.getPrivateKey();
loaded.getChain();   // List<X509Certificate>
```

### 1.5 Certificate Inspection

```java
CertInfo info = CertInfo.of(cert);

info.getSubject();                         // "CN=api.example.com"
info.getIssuer();
info.getSerialNumber();
info.getNotBefore();                       // Instant
info.getNotAfter();                        // Instant
info.isExpired();                          // boolean
info.isExpiredIn(Duration.ofDays(30));     // boolean — useful for monitoring
info.isCA();
info.getSans();                            // List<String>
info.getKeyUsages();                       // Set<KeyUsage>
info.getExtendedKeyUsages();               // Set<ExtendedKeyUsage>
info.getOcspUrls();                        // List<String> from AIA extension
info.getCrlUrls();                         // List<String> from CDP extension
info.getFingerprint(HashAlgorithm.SHA256); // hex string, e.g. "AB:CD:..."
info.getPublicKeyAlgorithm();              // "RSA", "EC"
info.getPublicKeySize();                   // 2048, 256, etc.
```

### 1.6 CRL Generation

```java
X509CRL crl = Crl.issued()
    .issuer(caCert, caPrivateKey)
    .nextUpdate(Duration.ofHours(24))
    .revoke(cert1, RevocationReason.KEY_COMPROMISE)
    .revoke(cert2, RevocationReason.PRIVILEGE_WITHDRAWN)
    .build();

byte[] crlDer = Crls.toDer(crl);
String crlPem = Crls.toPem(crl);
```

---

## Module 2 — `easy-pki-validation`

**Maven artifact:** `io.github.yourname:easy-pki-validation`

**Depends on:** `easy-pki-core`

The most valuable module from a practical standpoint. Handles certificate path validation, OCSP, and CRL — including corporate environments with custom/internal PKI endpoints.

### 2.1 Basic Chain Validation

```java
ValidationResult result = CertValidator.of(cert)
    .chain(intermediate, root)
    .validate();

result.isValid();
result.getErrors();           // List<ValidationError>
result.getValidationPath();   // List<X509Certificate> — built chain
```

### 2.2 OCSP Validation

```java
ValidationResult result = CertValidator.of(cert)
    .chain(intermediate, root)
    .ocsp()
        .url("http://ocsp.corp.internal")  // override URL from certificate AIA
        .timeout(Duration.ofSeconds(5))
        .done()
    .validate();
```

### 2.3 CRL Validation (with caching)

```java
ValidationResult result = CertValidator.of(cert)
    .chain(intermediate, root)
    .crl()
        .cache(Duration.ofMinutes(30))
        .proxy("http://proxy.corp:3128")   // for corporate environments
        .done()
    .validate();
```

### 2.4 OCSP with CRL Fallback

```java
// Recommended for production
ValidationResult result = CertValidator.of(cert)
    .chain(intermediate, root)
    .ocspWithCrlFallback()
    .timeout(Duration.ofSeconds(10))
    .validate();

result.isValid();
result.isRevoked();
result.getRevokeReason();   // KEY_COMPROMISE, CA_COMPROMISE, UNSPECIFIED, ...
result.getRevokeTime();     // Instant
```

### 2.5 Automatic Chain Building

```java
// You only have the end-entity cert and a pool of intermediates
CertChain chain = ChainBuilder.of(cert)
    .intermediates(intermediatePool)    // Collection<X509Certificate>
    .trustStore(trustStore)             // KeyStore or Collection<X509Certificate>
    .build();                           // Throws if chain cannot be built

chain.getCertificates();    // ordered: end-entity → ... → root
chain.getRoot();
chain.validate();           // ValidationResult
```

### 2.6 ValidationResult

```java
public interface ValidationResult {
    boolean isValid();
    boolean isRevoked();
    boolean isExpired();
    boolean isNotYetValid();
    boolean isTrusted();
    RevocationReason getRevokeReason();     // nullable
    Instant getRevokeTime();               // nullable
    List<X509Certificate> getValidationPath();
    List<ValidationError> getErrors();
}
```

---

## Module 3 — `easy-pki-spring-boot-starter`

**Maven artifact:** `io.github.yourname:easy-pki-spring-boot-starter`

**Depends on:** `easy-pki-core`, `easy-pki-validation`, Spring Boot 3.x

Auto-configures PKI infrastructure as Spring beans. Zero code required for basic setup.

### 3.1 Configuration (application.yml)

```yaml
easy-pki:
  trust-store:
    path: classpath:truststore.p12
    password: changeit
    type: PKCS12
  key-store:
    path: /etc/ssl/keystore.p12
    password: ${KEYSTORE_PASSWORD}
    type: PKCS12
  validation:
    ocsp-timeout: 5s
    crl-cache-ttl: 30m
    mode: OCSP_WITH_CRL_FALLBACK   # OCSP | CRL | OCSP_WITH_CRL_FALLBACK | NONE
    proxy: http://proxy.corp:3128  # optional
  monitoring:
    enabled: true
    warn-before: 30d               # emit warning event this many days before expiry
    check-interval: 12h
```

### 3.2 Auto-configured Beans

The following beans are created automatically and can be injected:

| Bean type | Description |
|---|---|
| `CertValidator` | Pre-configured validator with trust store and validation mode |
| `CertificateMonitor` | Monitors configured keystores for expiring certificates |
| `Pkcs12Bundle` (qualified) | Loaded key store bundle |

```java
@Service
public class TlsService {

    private final CertValidator certValidator;

    public TlsService(CertValidator certValidator) {
        this.certValidator = certValidator;
    }

    public void validateClientCert(X509Certificate clientCert) {
        ValidationResult result = certValidator.validate(clientCert);
        if (!result.isValid()) {
            throw new CertificateValidationException(result.getErrors());
        }
    }
}
```

### 3.3 Certificate Expiry Monitoring Events

```java
@EventListener
public void onCertExpiring(CertExpiringEvent event) {
    log.warn("Certificate expiring in {} days: {}",
        event.getDaysLeft(),
        event.getCertificate().getSubjectX500Principal());

    alertService.send(
        "Certificate expiry warning",
        event.getCertificate()
    );
}

@EventListener
public void onCertExpired(CertExpiredEvent event) {
    // Certificate already expired — critical alert
}
```

### 3.4 Spring Security mTLS Integration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           CertValidator certValidator) throws Exception {
        http
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService())
            )
            .addFilterBefore(
                new EasyPkiClientCertFilter(certValidator),
                X509AuthenticationFilter.class
            );
        return http.build();
    }
}
```

### 3.5 Actuator Health Endpoint

When `management.endpoints.web.exposure.include=health` is configured, the starter automatically adds a PKI health indicator:

```json
{
  "status": "UP",
  "components": {
    "pki": {
      "status": "UP",
      "details": {
        "keystore": "OK",
        "truststore": "OK",
        "certificates": {
          "api.example.com": {
            "status": "OK",
            "expiresIn": "287 days"
          }
        }
      }
    }
  }
}
```

---

## Module 4 — `easy-pki-test`

**Maven artifact:** `io.github.yourname:easy-pki-test`

**Scope:** `test` (never include in production)

Generates a complete PKI hierarchy in memory for unit and integration tests. No files, no external processes.

### 4.1 Basic Usage

```java
// Spin up a full CA hierarchy in 3 lines
TestPki pki = TestPki.create()
    .withRootCa("CN=Test Root CA")
    .withIntermediateCa("CN=Test Issuing CA")
    .build();

// Issue certificates
X509Certificate serverCert = pki.issueCert()
    .subject("CN=localhost")
    .san("localhost", "127.0.0.1")
    .build();

X509Certificate clientCert = pki.issueCert()
    .subject("CN=test-client, OU=TestUsers")
    .extendedKeyUsage(TLS_CLIENT)
    .build();
```

### 4.2 Special Test Scenarios

```java
// Expired certificate
X509Certificate expiredCert = pki.issueCert()
    .subject("CN=expired.test")
    .validFrom(Instant.now().minus(60, DAYS))
    .validTo(Instant.now().minus(1, DAYS))
    .build();

// Not yet valid
X509Certificate futureCart = pki.issueCert()
    .subject("CN=future.test")
    .validFrom(Instant.now().plus(10, DAYS))
    .build();

// Revoked certificate
X509Certificate revokedCert = pki.issueCert()
    .subject("CN=revoked.test")
    .thenRevoke(RevocationReason.KEY_COMPROMISE);

// Revocation check against in-memory OCSP/CRL
pki.getOcspResponder();   // in-memory OCSP responder for testing
pki.getCrl();             // current CRL containing revoked certs
```

### 4.3 JUnit 5 Extension

```java
@ExtendWith(EasyPkiExtension.class)
class CertValidationServiceTest {

    @InjectTestPki
    TestPki pki;

    @Autowired
    CertValidationService service;

    @Test
    void shouldAcceptValidCert() {
        X509Certificate cert = pki.issueCert()
            .subject("CN=valid-client")
            .build();

        assertThat(service.validate(cert).isValid()).isTrue();
    }

    @Test
    void shouldRejectExpiredCert() {
        X509Certificate cert = pki.issueCert().expired().build();

        ValidationResult result = service.validate(cert);
        assertThat(result.isValid()).isFalse();
        assertThat(result.isExpired()).isTrue();
    }

    @Test
    void shouldRejectRevokedCert() {
        X509Certificate cert = pki.issueCert()
            .subject("CN=revoked-client")
            .thenRevoke(KEY_COMPROMISE);

        ValidationResult result = service.validate(cert);
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(KEY_COMPROMISE);
    }
}
```

### 4.4 Spring Boot Test Support

```java
@SpringBootTest
@AutoConfigureEasyPki   // registers TestPki as a Spring bean
class IntegrationTest {

    @Autowired
    TestPki testPki;

    @Autowired
    MockMvc mockMvc;

    @Test
    void shouldAllowMtlsWithValidCert() throws Exception {
        X509Certificate cert = testPki.issueCert()
            .subject("CN=test-user")
            .build();

        mockMvc.perform(get("/api/secure")
            .with(x509(cert)))
            .andExpect(status().isOk());
    }
}
```

---

## Technical Stack

| Component | Technology |
|---|---|
| Cryptography core | BouncyCastle 1.78+ (`bcprov-jdk18on`, `bcpkix-jdk18on`) |
| Build system | Maven 3.9+, multi-module |
| Minimum Java version | Java 17 (LTS) |
| Spring Boot support | Spring Boot 3.x (Spring Framework 6) |
| Testing | JUnit 5, AssertJ, Mockito |
| Documentation | Javadoc + MkDocs → GitHub Pages |
| CI/CD | GitHub Actions |
| Code quality | Checkstyle, SpotBugs, JaCoCo (>80% coverage) |
| Publishing | Maven Central via Sonatype OSSRH |

---

## Roadmap

### v0.1.0 — Core Foundation
> Goal: usable library with key generation, certificate creation and I/O

- [ ] Project skeleton: Maven multi-module, GitHub Actions CI
- [ ] `Keys` — RSA and EC key pair generation
- [ ] `Certificate.selfSigned()` builder
- [ ] `Certificate.signed()` builder
- [ ] Basic extensions: CA, path length, key usage, EKU, SAN
- [ ] `Certificates` — PEM/DER read and write
- [ ] `PrivateKeys` — PEM read (plain and encrypted)
- [ ] `Pkcs12` — create and load PKCS#12 bundles
- [ ] `CertInfo` — certificate inspection API
- [ ] Unit tests for all core features
- [ ] Basic README with comparison vs raw BouncyCastle

### v0.2.0 — Validation
> Goal: production-ready certificate validation for corporate PKI

- [ ] `CertValidator` — chain validation (no revocation)
- [ ] OCSP validation with configurable URL override
- [ ] CRL validation with in-memory caching
- [ ] OCSP with CRL fallback mode
- [ ] Proxy support for OCSP/CRL HTTP requests
- [ ] `ChainBuilder` — automatic trust path construction
- [ ] Full `ValidationResult` API
- [ ] Tests with real OCSP/CRL scenarios using `easy-pki-test`
- [ ] `CRL` generation (moved from core to this module)
- [ ] Javadoc for all public API

### v0.3.0 — Spring Boot Starter
> Goal: zero-config Spring Boot integration

- [ ] `easy-pki-spring-boot-starter` module
- [ ] `application.yml` configuration binding
- [ ] `CertValidator` auto-configuration bean
- [ ] `CertificateMonitor` with configurable schedule
- [ ] Spring Events: `CertExpiringEvent`, `CertExpiredEvent`
- [ ] Spring Boot Actuator health indicator
- [ ] Spring Security mTLS filter integration
- [ ] Integration tests with Spring Boot Test
- [ ] Spring Boot starter documentation

### v0.4.0 — Test Module
> Goal: first-class test support

- [ ] `easy-pki-test` module
- [ ] `TestPki` — in-memory CA hierarchy
- [ ] In-memory OCSP responder
- [ ] CRL generation for revoked test certs
- [ ] `EasyPkiExtension` for JUnit 5
- [ ] `@InjectTestPki` annotation
- [ ] `@AutoConfigureEasyPki` for Spring Boot Test
- [ ] Examples for common test scenarios

### v1.0.0 — Stable Release
> Goal: stable, documented, published to Maven Central

- [ ] API freeze — semantic versioning guarantee
- [ ] Full Javadoc on all public classes and methods
- [ ] MkDocs documentation site (GitHub Pages)
  - Getting started guide
  - Module-by-module reference
  - Migration guide from raw BouncyCastle
  - Common recipes cookbook
- [ ] Published to Maven Central
- [ ] GitHub Releases with changelogs
- [ ] Comparison table in README: `easy-pki` vs BouncyCastle vs `cryptacular`

### v1.x — Future Ideas
- PKCS#7 / CMS signing and verification
- PKCS#10 CSR generation and parsing
- Timestamp Authority (TSA) client
- Kotlin DSL extension module
- GraalVM native image support (reflection config)
- Quarkus extension

---

## Publishing & Promotion

### Maven Central

Publishing to Maven Central (via Sonatype OSSRH) is required for adoption. Steps:
1. Register on [issues.sonatype.org](https://issues.sonatype.org) and claim a `groupId`
2. Configure GPG signing in Maven `settings.xml`
3. Add Maven release plugin and Sonatype staging plugin
4. Automate release via GitHub Actions on tag push

### GitHub Repository

- Meaningful README with code examples front and center
- Side-by-side comparison: `easy-pki` vs raw BouncyCastle (key differentiator)
- Badges: build status, Maven Central version, coverage, license
- GitHub Discussions enabled for community questions
- Issue templates for bug reports and feature requests

### Promotion

| Channel | Content |
|---|---|
| **Habr** | Article: "Как я устал от BouncyCastle и написал обёртку" |
| **dev.to** | English version: "Fluent PKI for Java — easy-pki library" |
| **Reddit r/java** | Launch post with benchmark / code comparison |
| **Twitter/X** | Short thread with before/after code snippets |
| **Awesome Java** | Submit PR to [akullpp/awesome-java](https://github.com/akullpp/awesome-java) |

---

## License

**Apache License 2.0** — most permissive, standard for open source Java libraries. Allows use in commercial products without restrictions.

---

*Last updated: 2025*
