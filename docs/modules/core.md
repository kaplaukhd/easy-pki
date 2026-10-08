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

## Subject DN

=== "RFC 4514 string"

    ```java
    .subject("CN=host, O=Acme, C=US")
    ```

=== "DnBuilder (fluent)"

    ```java
    .subject(dn -> dn.cn("host").o("Acme").c("US"))
    ```

Both produce identical results — pick whichever reads cleaner in your code.

String input is parsed by `X500Principal`, using its RFC 2253/4514 name
convention: the most-specific RDN is written first. The fluent builder uses
the same display order and treats attribute values as literals (escaping
commas, plus signs, leading `#` and spaces). A string may contain multi-valued
RDNs, for example `CN=host+UID=42,O=Acme,C=US`. Use JCA-supported keywords
or numeric OIDs; Bouncy Castle-specific aliases are not the string contract.

Both certificate builders also accept `.subject(X500Principal)`. The principal's
DER encoding is preserved, including RDN order and attribute value types.
Earlier snapshots reversed multi-component names on JCA readback; see the
[migration guide](../migration.md) before reissuing certificates.

For issuer-signed certificates and generated CRLs, AKI uses the issuer
certificate's SKI, including nonstandard valid identifiers. If SKI is absent,
the identifier is the SHA-1 hash of the issuer public-key BIT STRING, per
RFC 5280. This hash identifies a key; it is not the signature algorithm.

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

Encrypted output uses **PBES2 + PBKDF2-HMAC-SHA-256, 600,000 iterations,
AES-256-CBC**, with fresh random salt and IV on every write. PBES2/PBKDF2
keeps PKCS#8 interoperability with existing tools. The iteration default is
a library policy informed by [OWASP's PBKDF2 work-factor guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2),
not a PKCS#8 requirement or a FIPS certification claim. Measure cost on the
target system; reducing it weakens resistance to offline password guessing.
HMAC-SHA-256 and HMAC-SHA-512 are available for new output; old encrypted
formats, including the former defaults, remain readable.

```java
char[] password = "example-password".toCharArray(); // obtain securely in an application
try {
    var options = new PemEncryptionOptions(1_000_000, PemEncryptionOptions.Prf.HMAC_SHA256);
    String encrypted = PkiPrivateKeys.toPem(privateKey, password, options);
    PrivateKey restored = PkiPrivateKeys.fromPem(encrypted, password);
    PkiPrivateKeys.toFile(privateKey, Path.of("key.pem"), password, options);
} finally {
    Arrays.fill(password, '\0');
}
```

`PemEncryptionOptions` is immutable and holds no password. `char[]` overloads
are available for String/Reader/InputStream/file input and String/file output.
Operations clone caller arrays and clear their temporary copies on success
or failure. Caller arrays remain unchanged and must be cleared by the caller.
String overloads remain compatible but Strings cannot be erased; provider or
JVM-internal copies are also outside this clearing guarantee.

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

Omit `privateKey(...)` to create a trust-only store. Every certificate in
`getChain()` is saved as a separate trusted certificate entry, including
unrelated CA roots:

```java
Pkcs12Bundle trust = PkiPkcs12.create()
    .certificate(rootA)
    .chain(rootB, rootC)
    .alias("trusted")
    .password("changeit")
    .build();
trust.saveTo(Path.of("truststore.p12"));
```

New trust-only bundles assign the primary certificate the configured alias
(default `1`) and the remaining entries `<alias>-2`, `<alias>-3`, and so
on. The JCA provider may normalize alias case. On loading a trust-only store,
all trusted X.509 entries are retained in lexicographic alias order; the
first entry supplies `getAlias()` and `getCertificate()`. This is a flat
certificate collection, not necessarily an issuer chain. For example,
`trusted-10` sorts before `trusted-2`. A loaded store preserves its aliases
on re-export. Identity bundles retain the existing private-key entry and
leaf-first chain behavior.

## Inspection

`isSelfSigned()` returns false if the signature is invalid or cannot be verified
by the available JCA providers. Neither inspection method establishes trust,
checks expiry, or validates CA constraints. A key-rollover certificate can be
self-issued while being signed by a different key.

`PkiCertInfo` wraps an `X509Certificate` in an ergonomic, read-only view.

```java
PkiCertInfo info = PkiCertInfo.of(cert);

info.getSubject();                          // "CN=api.example.com"
info.getIssuer();
info.getSerialNumber();
info.getNotBefore();                        // Instant
info.getNotAfter();
info.isSelfIssued();  // subject and issuer names match
info.isSelfSigned();  // names match AND signature verifies with its own public key
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
| `serialNumber(BigInteger)` | random positive nonzero, at most 159 bits | accepts only `1..2^159-1`; at most 20 DER INTEGER value octets |
| `signatureAlgorithm(String)` | `SHA256with{RSA,ECDSA}` | SHA-384 / SHA-512 |
| `validFrom(Instant)` / `validUntil(Instant)` | now / `validFor` offset | historical dating |

All defaults follow current best practice. Override only when you have a
concrete reason.
