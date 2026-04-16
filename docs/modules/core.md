# easy-pki-core

The foundation module. No Spring dependencies — just BouncyCastle under the
hood and a fluent API on top.

## Key generation

```java
KeyPair rsa2048 = PkiKeys.rsa(2048);    // minimum allowed
KeyPair rsa4096 = PkiKeys.rsa(4096);
KeyPair ecP256  = PkiKeys.ec(Curve.P_256);
KeyPair ecP384  = PkiKeys.ec(Curve.P_384);
KeyPair ecP521  = PkiKeys.ec(Curve.P_521);
```

BouncyCastle is **never registered globally** — `PkiKeys` uses it as an
explicit provider so your application's JCA configuration stays intact.

## Self-signed certificates

```java
X509Certificate root = PkiCertificate.selfSigned()
    .subject("CN=Root CA, O=Acme")
    .keyPair(keys)
    .validFor(Duration.ofDays(3650))
    .isCA(true)
    .pathLength(1)
    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
    .build();
```

## Issuer-signed certificates

```java
X509Certificate leaf = PkiCertificate.signed()
    .subject("CN=host.example.org")
    .publicKey(leafKeys.getPublic())
    .issuer(issuerCert, issuerPrivateKey)
    .validFor(Duration.ofDays(365))
    .san(s -> s.dns("host.example.org").ip("10.0.0.1"))
    .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
    .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
    .ocsp("http://ocsp.example.org")
    .crlDistributionPoint("http://crl.example.org/ca.crl")
    .build();
```

## Subject DN — two forms

=== "RFC 4514 string"

    ```java
    .subject("CN=host, O=Acme, C=US")
    ```

=== "DnBuilder (fluent)"

    ```java
    .subject(dn -> dn.cn("host").o("Acme").c("US"))
    ```

Both produce identical results — pick whichever reads cleaner in your code.

## I/O

### Certificates

```java
// Write
String pem  = PkiCertificates.toPem(cert);
byte[] der  = PkiCertificates.toDer(cert);
PkiCertificates.toFile(cert, Path.of("cert.pem"));
PkiCertificates.toFile(List.of(leaf, intermediate, root), Path.of("chain.pem"));

// Read
X509Certificate c        = PkiCertificates.fromPem(pem);
X509Certificate c2       = PkiCertificates.fromDer(der);
X509Certificate c3       = PkiCertificates.fromFile(Path.of("cert.pem"));
List<X509Certificate> ch = PkiCertificates.allFromFile(Path.of("chain.pem"));
```

### Private keys

```java
// Write — modern PKCS#8, AES-256-CBC when a password is given
String pem       = PkiPrivateKeys.toPem(privateKey);
String encrypted = PkiPrivateKeys.toPem(privateKey, "changeit");
PkiPrivateKeys.toFile(privateKey, Path.of("key.pem"));
PkiPrivateKeys.toFile(privateKey, Path.of("key.pem"), "changeit");

// Read — supports unencrypted & encrypted PKCS#8, plus legacy
// OpenSSL PKCS#1 (RSA) and EC-specific formats
PrivateKey k  = PkiPrivateKeys.fromPem(pem);
PrivateKey k2 = PkiPrivateKeys.fromPem(encrypted, "changeit");
PrivateKey k3 = PkiPrivateKeys.fromFile(Path.of("key.pem"), "changeit");
```

## PKCS#12

```java
// Create
Pkcs12Bundle bundle = PkiPkcs12.create()
    .certificate(leaf)
    .privateKey(leafKey)
    .chain(intermediate, root)
    .alias("server")
    .password("changeit")
    .build();

bundle.saveTo(Path.of("keystore.p12"));
byte[] bytes = bundle.toBytes();

// Load
Pkcs12Bundle loaded = PkiPkcs12.load(Path.of("keystore.p12"), "changeit");
loaded.getCertificate();  // X509Certificate — leaf
loaded.getPrivateKey();   // PrivateKey, or null for trust-only bundles
loaded.getChain();        // List<X509Certificate> — full chain (leaf first)
loaded.getAlias();
```

The output is interoperable with `KeyStore.getInstance("PKCS12")` — verified
in the test suite.

## Inspection

`PkiCertInfo` wraps an `X509Certificate` in an ergonomic, read-only view.

```java
PkiCertInfo info = PkiCertInfo.of(cert);

info.getSubject();                          // "CN=api.example.com"
info.getIssuer();
info.getSerialNumber();
info.getNotBefore();                        // Instant
info.getNotAfter();
info.isSelfSigned();
info.isExpired();
info.isNotYetValid();
info.isExpiringWithin(Duration.ofDays(30)); // monitoring helper

info.isCA();
info.getPathLength();                       // Integer, null when not a CA

info.getKeyUsages();                        // Set<KeyUsage>
info.getExtendedKeyUsages();                // Set<ExtendedKeyUsage>
info.getSans();                             // List<SubjectAlternativeName>

info.getOcspUrls();                         // List<String> — AIA extension
info.getCrlUrls();                          // List<String> — CDP extension

info.getPublicKeyAlgorithm();               // "RSA" / "EC" / ...
info.getPublicKeySize();                    // 2048, 256, ...

info.getFingerprint(HashAlgorithm.SHA256);  // "AB:CD:EF:..."
```

## Key usage and extended key usage

Use the `KeyUsage` and `ExtendedKeyUsage` enums. They map to the standard
RFC 5280 values and can be round-tripped through `PkiCertInfo`.

`KeyUsage` values: `DIGITAL_SIGNATURE`, `NON_REPUDIATION`, `KEY_ENCIPHERMENT`,
`DATA_ENCIPHERMENT`, `KEY_AGREEMENT`, `KEY_CERT_SIGN`, `CRL_SIGN`,
`ENCIPHER_ONLY`, `DECIPHER_ONLY`.

`ExtendedKeyUsage` values: `TLS_SERVER`, `TLS_CLIENT`, `CODE_SIGNING`,
`EMAIL_PROTECTION`, `TIME_STAMPING`, `OCSP_SIGNING`.

## Subject Alternative Name

```java
.san(s -> s.dns("example.org")
           .dns("*.example.org")
           .ip("10.0.0.1")
           .ip("2001:db8::1")
           .email("admin@example.org")
           .uri("https://example.org"))
```

## Advanced defaults

Every builder exposes escape hatches for uncommon cases:

| Builder method | Default | Override for |
|---|---|---|
| `serialNumber(BigInteger)` | random 20-byte positive | deterministic tests |
| `signatureAlgorithm(String)` | `SHA256with{RSA,ECDSA}` | SHA-384 / SHA-512 |
| `validFrom(Instant)` / `validUntil(Instant)` | now / `validFor` offset | historical dating |

All defaults follow current best practice. Override only when you have a
concrete reason.
