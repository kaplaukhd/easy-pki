# easy-pki-test

Self-contained test helpers: an in-memory CA hierarchy, an OCSP responder,
and a JUnit 5 extension. Consume with `<scope>test</scope>`.

## TestPki

### Minimal hierarchy

```java
TestPki pki = TestPki.create()
    .withRootCa("CN=Test Root CA")
    .withIntermediateCa("CN=Test Issuing CA")
    .build();
```

Defaults: RSA 2048 keys, 10-year root, 5-year intermediate,
`KEY_CERT_SIGN + CRL_SIGN` usages. Everything is customisable.

### Without an intermediate

```java
TestPki pki = TestPki.create().withRootCa("CN=Flat Root").build();
// pki.hasIntermediate() == false; leaves are signed directly by the root
```

### Accessors

```java
pki.getRootCa();             // X509Certificate
pki.getRootKeys();           // KeyPair
pki.getIntermediateCa();     // null if no intermediate
pki.getIntermediateKeys();
pki.getIssuerCa();           // effective issuer (intermediate or root)
pki.getIssuerPrivateKey();
pki.getChain();              // [intermediate, root] or [root]
pki.getTrustAnchors();       // [root]
```

## Issuing test leaves

```java
X509Certificate server = pki.issueCert()
    .subject("CN=localhost")
    .san("localhost", "127.0.0.1")     // auto-detects DNS / IP / email
    .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
    .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
    .validFor(Duration.ofDays(30))
    .build();
```

`.build()` returns the certificate; `.issue()` returns an `IssuedCert`
record bundling the cert with its freshly-generated key pair:

```java
IssuedCert client = pki.issueCert()
    .subject("CN=test-client")
    .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
    .issue();

sslContext.useClientCert(client.certificate(), client.privateKey());
```

### Special scenarios

```java
// Already expired — notBefore=-60d, notAfter=-1d
X509Certificate expired = pki.issueCert()
    .subject("CN=expired")
    .expired()
    .build();

// Not yet valid — notBefore=+30d
X509Certificate future = pki.issueCert()
    .subject("CN=future")
    .notYetValid()
    .build();

// Custom validity window
X509Certificate custom = pki.issueCert()
    .subject("CN=custom")
    .validFrom(Instant.parse("2030-01-01T00:00:00Z"))
    .validUntil(Instant.parse("2030-06-01T00:00:00Z"))
    .build();

// EC key instead of the default RSA 2048
IssuedCert ec = pki.issueCert()
    .subject("CN=ec-client")
    .ec(Curve.P_256)
    .issue();
```

### SAN auto-detection

```java
.san("host.example.org",    // DNS name
     "10.0.0.1",              // IPv4
     "2001:db8::1",           // IPv6
     "admin@example.org")     // e-mail
```

The builder recognises the type from the entry's shape. For exotic cases,
fall back to the explicit consumer form:

```java
.san(s -> s.uri("https://example.org/policy").dns("alias.example.org"))
```

## Revocation and CRL

```java
X509Certificate revoked = pki.issueCert()
    .subject("CN=bad")
    .thenRevoke(RevocationReason.KEY_COMPROMISE);  // issue + register
```

Or two-step:

```java
X509Certificate cert = pki.issueCert().subject("CN=later").build();
// ... use cert ...
pki.revoke(cert, RevocationReason.SUPERSEDED);
```

`TestPki.getCrl()` rebuilds a fresh CRL on every call, signed by the
effective issuer and covering every registered revocation:

```java
X509CRL crl = pki.getCrl();
```

Supply the test PKI's trust anchors separately from its certificate chain:

```java
ValidationResult result = CertValidator.of(cert)
    .chain(pki.getChain())
    .trustAnchors(pki.getTrustAnchors())
    .crl(pki.getCrl())
    .validate();
```

This exercises CRL-based revocation in your service tests. A chain alone,
including one created by `TestPki`, does not establish trust.

## In-memory OCSP responder

```java
try (TestOcspResponder ocsp = pki.startOcspResponder()) {
    X509Certificate leaf = pki.issueCert()
        .subject("CN=tls-server")
        .ocsp(ocsp.getUrl())         // embed AIA URL
        .build();

    ValidationResult result = CertValidator.of(leaf)
        .chain(pki.getChain())
        .trustAnchors(pki.getTrustAnchors())
        .ocsp()
        .validate();
}
```

The responder binds to `127.0.0.1` on a random port, signs responses with
the TestPki's issuer key, returns GOOD for unknown serials and REVOKED
(with the reason + timestamp recorded via `pki.revoke(...)`) for registered
revocations. Revocations made *after* the responder starts are reflected
immediately.

## JUnit 5 extension

```java
@ExtendWith(EasyPkiExtension.class)
class MyServiceTest {

    @InjectTestPki
    TestPki pki;      // fresh PKI per test method

    @Test
    void validCertIsAccepted() {
        X509Certificate cert = pki.issueCert().subject("CN=ok").build();
        assertThat(service.accept(cert)).isTrue();
    }

    @Test
    void testWithParameterInjection(@InjectTestPki(withIntermediate = false)
                                    TestPki rootOnly) {
        // rootOnly has no intermediate — leaves signed directly by the root
    }
}
```

`@InjectTestPki` attributes:

| Attribute | Default |
|---|---|
| `withIntermediate` | `true` |
| `rootSubject` | `CN=Test Root CA` |
| `intermediateSubject` | `CN=Test Issuing CA` |

The extension walks the class hierarchy, so annotated fields in superclasses
are populated too. It works inside `@Nested` classes when the annotation is
repeated on the nested class.

## Typical patterns

### Testing a service that validates OCSP

```java
@ExtendWith(EasyPkiExtension.class)
class AuthServiceTest {

    @InjectTestPki TestPki pki;

    @Test
    void revokedClientRejected() {
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {
            X509Certificate revoked = pki.issueCert()
                .subject("CN=bad-client")
                .ocsp(ocsp.getUrl())
                .thenRevoke(RevocationReason.KEY_COMPROMISE);

            assertThatThrownBy(() -> authService.login(revoked))
                .isInstanceOf(SecurityException.class);
        }
    }
}
```

### Testing a Spring Boot app with `@AutoConfigureMockMvc`

Use one class-scoped PKI for the Spring context and every test method.
`@DynamicPropertySource` is static and accepts **only** a
`DynamicPropertyRegistry`; it does not receive JUnit-injected parameters.
Do not combine this fixture with a per-test `@InjectTestPki` field, which would
issue client certificates from a different CA than the cached context trusts.

The example below is compiled and executed in `easy-pki-test` as
`WebSecurityExampleTest`. Its fixture exists before context initialization,
its file is removed after the class, and `@DirtiesContext` prevents reuse of
that context after cleanup. Protection is explicitly registered. Revocation
is disabled for this trust/filter example; `NONE` still requires explicit
trust. The servlet certificate attribute simulates the TLS container's output;
MockMvc does not exercise a TLS handshake.

Consumer tests need `easy-pki-test`, `easy-pki-spring-boot-starter`,
`spring-boot-starter-web` and `spring-boot-starter-test`. In this repository,
the Spring dependencies used to verify this example are test-scoped only.
Run `mvn -pl easy-pki-test -am -Dtest=WebSecurityExampleTest -Dsurefire.failIfNoSpecifiedTests=false test`.

```java
--8<-- "easy-pki-test/src/test/java/io/github/kaplaukhd/easypki/test/WebSecurityExampleTest.java:spring-example"
```
