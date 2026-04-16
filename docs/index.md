# easy-pki

**A fluent Java API for PKI operations.** BouncyCastle under the hood, an
ergonomic API on top.

What used to take 40–60 lines of low-level ceremony now fits in five readable
lines — and you get validation, Spring Boot auto-configuration and test
helpers in the same family of modules.

---

## At a glance

=== "Self-signed root CA"

    ```java
    KeyPair keys = PkiKeys.rsa(2048);

    X509Certificate cert = PkiCertificate.selfSigned()
        .subject("CN=example.com, O=MyOrg")
        .keyPair(keys)
        .validFor(Duration.ofDays(365))
        .isCA(true)
        .build();
    ```

=== "TLS leaf with SAN and OCSP"

    ```java
    X509Certificate leaf = PkiCertificate.signed()
        .subject("CN=api.example.com")
        .publicKey(serverKeys.getPublic())
        .issuer(intermediate, intermediateKeys.getPrivate())
        .validFor(Duration.ofDays(365))
        .san(s -> s.dns("api.example.com").ip("10.0.0.1"))
        .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
        .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
        .ocsp("http://ocsp.example.org")
        .build();
    ```

=== "Validate with OCSP + CRL fallback"

    ```java
    ValidationResult r = CertValidator.of(leaf)
        .chain(intermediate, root)
        .ocspWithCrlFallback()
        .validate();

    if (!r.isValid()) log.warn("Rejected: {}", r.getErrors());
    ```

=== "Test with an in-memory PKI"

    ```java
    @ExtendWith(EasyPkiExtension.class)
    class MyTest {
        @InjectTestPki TestPki pki;

        @Test
        void revokedCertIsRejected() {
            var revoked = pki.issueCert()
                .subject("CN=bad")
                .thenRevoke(RevocationReason.KEY_COMPROMISE);
            assertThat(service.accept(revoked)).isFalse();
        }
    }
    ```

---

## Why easy-pki?

Working with X.509 in Java today means choosing between:

- **`java.security` / JSSE** — limited, no support for custom OCSP/CRL
  endpoints, awkward for anything beyond textbook TLS.
- **BouncyCastle** — powerful but low-level. A single self-signed certificate
  requires `X500NameBuilder`, `JcaX509v3CertificateBuilder`, `ContentSigner`,
  a manual conversion back to `X509Certificate`, and forty lines of glue.

`easy-pki` is the missing middle layer — a fluent, discoverable API designed
for everyday tasks.

---

## Modules

<div class="grid cards" markdown>

- :material-certificate: **[`easy-pki-core`](modules/core.md)**

    Key generation, certificate builders, PEM/DER I/O, PKCS#12, inspection.

- :material-shield-check: **[`easy-pki-validation`](modules/validation.md)**

    Chain validation, OCSP, CRL (static + HTTP auto-fetch), chain building.

- :material-leaf: **[`easy-pki-spring-boot-starter`](modules/spring-boot.md)**

    Auto-configuration, expiry monitor, Actuator health, mTLS filter.

- :material-test-tube: **[`easy-pki-test`](modules/testing.md)**

    In-memory CA hierarchy, OCSP responder, JUnit 5 extension.

</div>

---

## Design principles

- **One obvious way.** Each task has a single discoverable entry point.
- **No magic global state.** BouncyCastle is never registered in the JCA
  provider list — your application's security configuration stays untouched.
- **Fail loudly at the boundary.** Malformed input and missing required fields
  throw clear, actionable exceptions.
- **Secure defaults.** Minimum RSA 2048. Random 20-byte serials. AES-256-CBC
  for encrypted PKCS#8. SHA-256 signatures.
- **Interoperable.** Input and output always conform to JCA types — drop down
  to standard APIs when needed.

---

## Next steps

- [Install and run your first example :octicons-arrow-right-24:](getting-started.md)
- [Common recipes cookbook :octicons-arrow-right-24:](cookbook.md)
- [Migrating from raw BouncyCastle :octicons-arrow-right-24:](migration.md)
