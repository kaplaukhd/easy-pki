# Getting started

## Requirements

- **Java 17** or later
- **Maven 3.9+** (or Gradle, if that's your build)

## Installation

Depend on only the modules you need.

=== "Maven"

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

=== "Gradle (Kotlin)"

    ```kotlin
    implementation("io.github.kaplaukhd:easy-pki-core:1.0.0")
    implementation("io.github.kaplaukhd:easy-pki-validation:1.0.0")
    implementation("io.github.kaplaukhd:easy-pki-spring-boot-starter:1.0.0")
    testImplementation("io.github.kaplaukhd:easy-pki-test:1.0.0")
    ```

---

## Your first PKI

Let's build a root CA, an intermediate CA and a server certificate — a
realistic three-cert chain.

### 1. Generate keys

```java
KeyPair rootKeys         = PkiKeys.rsa(4096);
KeyPair intermediateKeys = PkiKeys.rsa(2048);
KeyPair serverKeys       = PkiKeys.ec(Curve.P_256);
```

Supported: `rsa(2048|3072|4096)` and `ec(Curve.P_256|P_384|P_521)`.
Minimum RSA size is 2048 bits — weaker keys are rejected by construction.

### 2. Issue the root CA

```java
X509Certificate root = PkiCertificate.selfSigned()
    .subject("CN=Acme Root CA, O=Acme, C=US")
    .keyPair(rootKeys)
    .validFor(Duration.ofDays(3650))
    .pathLength(1)                               // implies isCA=true
    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
    .build();
```

Defaults applied automatically:

- Random 20-byte positive serial number (RFC 5280 §4.1.2.2).
- Signature algorithm `SHA256withRSA` (RSA keys) or `SHA256withECDSA`
  (EC keys).
- `notBefore = now` if not specified.
- `SubjectKeyIdentifier` derived from the public key.
- `AuthorityKeyIdentifier` set (for a self-signed cert, equal to SKI).

### 3. Issue the intermediate CA

```java
X509Certificate intermediate = PkiCertificate.signed()
    .subject("CN=Acme Issuing CA, O=Acme")
    .publicKey(intermediateKeys.getPublic())
    .issuer(root, rootKeys.getPrivate())
    .validFor(Duration.ofDays(1825))
    .pathLength(0)
    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
    .build();
```

### 4. Issue the end-entity TLS certificate

```java
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

### 5. Save the bundle

```java
PkiPkcs12.create()
    .certificate(server)
    .privateKey(serverKeys.getPrivate())
    .chain(intermediate, root)
    .alias("server")
    .password("changeit")
    .build()
    .saveTo(Path.of("keystore.p12"));
```

That's it — a full three-cert PKI with modern defaults in under 30 lines.

---

## What next?

- [Core module guide :octicons-arrow-right-24:](modules/core.md) — more on
  key generation, PEM/DER, PKCS#12 and certificate inspection.
- [Validation module guide :octicons-arrow-right-24:](modules/validation.md)
  — chain validation, OCSP, CRL.
- [Spring Boot starter guide :octicons-arrow-right-24:](modules/spring-boot.md)
  — auto-configuration, monitoring, Actuator, mTLS.
- [Cookbook :octicons-arrow-right-24:](cookbook.md) — copy-pasteable recipes.
