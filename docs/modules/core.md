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
KeyPair ed25519 = PkiKeys.ed25519();
```

BouncyCastle is **never registered globally** — `PkiKeys` uses it as an
explicit provider so your application's JCA configuration stays intact.

Ed25519 is inferred automatically by certificate builders and `PkiSigner.jca(key)`.
This also works after PEM/PKCS#12 reload when the JDK calls the key algorithm
`EdDSA`: its named parameters distinguish Ed25519 from Ed448. Ed448 is not
inferred as Ed25519. Certificate PEM/DER, plain/encrypted PKCS#8 and PKCS#12
round trips are covered by independent JCA signature and PKIX checks.
CRL generation and the `TestPki` OCSP responder also infer Ed25519, including
reloaded JDK keys; GOOD and REVOKED workflows are tested.

## Self-signed certificates

For role-specific issuance, use the [certificate profiles](#certificate-profiles)
below. The generic builders shown here remain available without profile checks.

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

Self-signed certificates also support `.san(...)` and `.extendedKeyUsage(...)`:

```java
X509Certificate localTls = PkiCertificate.selfSigned()
    .subject("CN=localhost")
    .keyPair(PkiKeys.ed25519())
    .validFor(Duration.ofDays(30))
    .san(s -> s.dns("localhost").ip("127.0.0.1").ip("::1"))
    .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
    .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
    .build();
```

SAN values accumulate in insertion order, including duplicates; EKU values
accumulate with deduplication. Both are encoded as noncritical extensions,
consistently with the issued builder. This supplies certificate metadata;
it does not configure a TLS server or establish trust in a self-signed leaf.

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

## Certificate profiles

Profiles add consistent role extensions and validate the request before calling
the certificate signer. Select an entry point, or call `.profile(...)` on an
existing builder; selecting a profile before or after its settings has the same
effect. Mandatory defaults are combined with explicit KU/EKU additions, and
conflicting additions are rejected.

| Profile | BasicConstraints | KeyUsage | EKU | Identity and path |
|---|---|---|---|---|
| `PkiCertificate.rootCa()` | CA, critical | keyCertSign + cRLSign, critical | absent | self-signed; nonempty subject; optional path length |
| `PkiCertificate.intermediateCa()` | CA, critical | keyCertSign + cRLSign, critical | absent | issuer identity required; default pathLength=0 |
| `PkiCertificate.tlsServer()` | not CA, critical | digitalSignature, critical | serverAuth only, noncritical | explicit DNS/IP SAN required; CN alone is insufficient |
| `PkiCertificate.tlsClient()` | not CA, critical | digitalSignature, critical | clientAuth only, noncritical | explicit subject or SAN identity; no server names added |

```java
KeyPair rootKeys = PkiKeys.ed25519();
X509Certificate root = PkiCertificate.rootCa()
    .subject("CN=Private Root CA")
    .keyPair(rootKeys)
    .pathLength(1)
    .validFor(Duration.ofDays(3650))
    .build();
PkiIdentity rootIdentity = PkiIdentity.of(root, rootKeys.getPrivate());

KeyPair issuingKeys = PkiKeys.ec(Curve.P_256);
X509Certificate issuingCa = PkiCertificate.intermediateCa()
    .subject("CN=Private Issuing CA")
    .keyPair(issuingKeys)
    .issuer(rootIdentity)
    .validFor(Duration.ofDays(1825))
    .build();
PkiIdentity issuer = PkiIdentity.of(issuingCa, issuingKeys.getPrivate(), root);

X509Certificate server = PkiCertificate.tlsServer()
    .publicKey(serverPublicKey)
    .issuer(issuer)
    .san(s -> s.dns("service.example.com").ip("192.0.2.10"))
    .validFor(Duration.ofDays(90))
    .build();

X509Certificate client = PkiCertificate.tlsClient()
    .subject("CN=worker-17")
    .publicKey(clientPublicKey)
    .issuer(issuer)
    .validFor(Duration.ofDays(90))
    .build();
```

Issued profiles require `.issuer(PkiIdentity)`. That overload retains the
supplied issuer chain for preflight and does not perform another possession
challenge. Raw `signed()` still accepts the existing certificate/private-key
and certificate/signer overloads. Calling those overloads after `issuer(identity)`
replaces the signing source and clears the retained identity, so a profile
cannot accidentally reuse constraints from a previous issuer.

Subject key families are RSA, RSA-PSS, EC and Ed25519. Agreement-only X25519/X448
keys cannot receive signing usages through these profiles. For a plain RSA TLS
server key, explicitly adding `KEY_ENCIPHERMENT` is allowed for legacy key
transport; it is never added automatically and is rejected for RSA-PSS, EC,
Ed25519 and client profiles. CA profiles reject unrelated KU bits and all EKU;
TLS profiles reject CA flags, path lengths, unrelated KU and additional EKU.

### Issuer preflight and validity

Every supplied issuer-chain certificate must have a nonempty CA subject,
critical CA BasicConstraints and explicit `keyCertSign`. The child's encoded
validity must fit within every supplied CA's validity interval. Exact endpoints
are allowed. Profiles normalize times down to whole seconds, reject intervals
that collapse after normalization, and support encoded years 1950–9999.
Historical/future windows are permitted when explicitly supplied and contained;
no lifetime is silently clamped or chosen for the caller.

Path-length checks count non-self-issued CAs below each supplied ancestor;
leaves and same-DN rollover CAs do not consume a level. A new intermediate's
declared path budget must also fit the remaining allowance of every supplied
ancestor. Root CA defaults have no path-length restriction; intermediate
defaults permit leaf issuance only. This budget check and validity containment
are conservative library issuance policies, beyond ordinary PKIX path acceptance.

Name constraints, policy constraints, policy mappings and inhibitAnyPolicy in a
supplied CA are currently rejected, even when noncritical. Other unprocessed
critical extensions are rejected as well. Issuer EKU must permit the selected
TLS purpose (or anyExtendedKeyUsage); issuing a CA beneath an EKU-bearing issuer
is outside this bounded policy and fails. Constraints are checked before any
certificate signature request; a returned profile certificate's signature is
also verified against the expected issuing key.

The check uses the provided identity chain only. It does not discover missing
ancestors, establish trust, check revocation, authorize names, or certify public
Web PKI/CA-Browser Forum compliance. Keep application issuance authorization and
the validation module's acceptance policy separate. `PkiIdentity` construction
itself already performs a key-possession signature, before it reaches the builder.

### TLS identities

Server SANs accept DNS names and IP literals only; client SANs additionally
accept ASCII mailbox and absolute URI identities. A client can instead use an
explicit nonempty subject. Profiles never derive a server name from CN or copy
the issuer's names into a client certificate.

DNS input uses ASCII LDH labels (1–63 characters, total at most 253), with no
trailing dot. Single-label private names are allowed. A wildcard must be the
entire leftmost label with at least two following labels. Supply international
names as application-prepared ASCII A-labels. IP literals use the IP SAN type;
CIDR/masks are rejected. Mailboxes use a bounded ASCII dot-atom form; client URI
values must be absolute ASCII URIs with a nonempty scheme-specific part. No DNS
resolution, public-suffix, URI-scheme policy, mailbox ownership or deliverability
check is performed. Original text is checked before relying on ASN.1 values,
preventing Unicode truncation from turning invalid input into a different name.

An issued TLS certificate may omit its subject when SAN identifies it; SAN is
then critical. With a nonempty subject SAN is noncritical. Self-signed TLS
profiles use `selfSigned().profile(CertificateProfile.TLS_SERVER)` or
`TLS_CLIENT` and always require a nonempty subject, because it is also the issuer.
Ordinary unprofiled builders keep their previous settings and SAN behavior.

## Signing without exporting private keys

Both certificate builders use `PkiSigner`. The existing `.keyPair(...)` and
`.issuer(certificate, privateKey)` paths remain convenience adapters with the
same RSA/EC defaults and named algorithm overrides, with Ed25519 inference added.

For an opaque JCA key handle, choose its provider explicitly:

```java
PkiSigner signer = PkiSigner.jca(issuerKeyHandle, "SHA256withRSA", provider);

X509Certificate leaf = PkiCertificate.signed()
    .subject("CN=service")
    .publicKey(servicePublicKey)
    .issuer(issuerCertificate, signer)
    .validFor(Duration.ofDays(30))
    .build();

X509Certificate root = PkiCertificate.selfSigned()
    .subject("CN=Root CA")
    .signer(issuerPublicKey, signer)
    .isCA(true)
    .validFor(Duration.ofDays(3650))
    .build();
```

`provider` can be an unregistered `java.security.Provider` instance, or use
the overload accepting a registered provider's name. Name lookup captures
the instance once. Explicit selection never falls back to another provider
or changes the global provider list. Without a provider argument, normal JCA
selection applies. Each JCA adapter call creates independent signing state;
the application retains ownership of its key handle and provider resources.

A backend that does not expose a Java `PrivateKey` can implement the contract:

```java
PkiSigner signer = new PkiSigner() {
    public String signatureAlgorithm() { return "SHA256withRSA"; }
    public byte[] sign(byte[] content) throws GeneralSecurityException {
        return signingService.signSha256WithRsa(keyId, content);
    }
};
```

The backend receives the **complete DER TBSCertificate**, not a digest; it
performs the declared hashing/signing operation and returns the X.509 signature
bytes. ECDSA must return DER `(r, s)`, not raw `r || s`; do not return a CMS
wrapper. The name must have an X.509 algorithm mapping in the bundled BC version,
and the backend must use those parameters and the key corresponding to the
supplied public key/issuer certificate. The public key must be encodable as
SubjectPublicKeyInfo. The contract requires no private-key encoding or BC types.

Configure the algorithm on an explicit signer. Combining it with the builder's
`signatureAlgorithm(...)` is rejected in either order. Replacing `keyPair(...)`
with `signer(...)`, or one `issuer(...)` overload with the other, replaces the
previous signing source. Each build gets a fresh TBS buffer; the JCA adapter
also creates a fresh signature operation. Custom implementations define their
own concurrency/resource policy; builders
do not close backends or destroy keys. Checked signing failures retain their
cause in an `IllegalStateException`, and null/empty signatures are rejected.

Tests use an opaque key whose `getEncoded()` throws, serviced by a local test
provider. This checks the no-export path without claiming integration with a
physical HSM. CRL signer integration is outside this certificate-signing API.

### Explicit RSA-PSS parameters

```java
var parameters = RsaPssParameters.sha256(); // SHA-256, MGF1/SHA-256, 32-byte salt
PkiSigner signer = PkiSigner.rsaPss(rsaPrivateKey, parameters);
// Custom policy: new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA384, 18).

X509Certificate certificate = PkiCertificate.selfSigned()
    .subject("CN=PSS Root")
    .signer(rsaPublicKey, signer)
    .isCA(true)
    .validFor(Duration.ofDays(365))
    .build();
```

The immutable configuration selects the message digest, MGF1 digest and salt
length independently. Trailer field 1 is fixed. Null digests, negative salt
lengths, unsupported parameter types and mismatched algorithm/parameter
declarations are rejected. Whether the salt fits the key and the provider
supports the combination is checked when signing. SHA-1 is retained as an
explicit compatibility choice; the preset uses SHA-256.

The same parameters drive JCA signing and both X.509 AlgorithmIdentifiers.
`PkiSigner.rsaPss` also accepts a provider instance or name. SunRsaSign supports
the custom SHA-256/MGF1-SHA-384 policy above; BC 1.86 rejects different message/MGF digests.
Selecting such an unsupported provider fails without changing parameters or
falling back to another provider. Normal JCA selection inspects the signing
key before applying parameters, including opaque key handles.

Custom PSS backends declare `signatureAlgorithm()` as `RSASSA-PSS` and override
`signatureParameters()` with a standard `PSSParameterSpec`; its default is
`null` for existing signers. Generic `RSASSA-PSS` without explicit parameters
is rejected. Existing digest-specific named overrides remain available where
their selected provider supports them.

## Signing identities

```java
PkiIdentity identity = PkiIdentity.of(leaf, leafSigner, intermediate, root);
PkiIdentity softwareIdentity = PkiIdentity.of(leaf, leafPrivateKey, intermediate);
PkiIdentity loadedIdentity = PkiIdentity.fromPkcs12(pkcs12IdentityBundle);

identity.getSigner();       // signing operation / key handle
identity.getCertificate();  // leaf
identity.getChain();        // immutable leaf-first presentation chain
identity.getPrivateKey();   // Optional: present only for private-key / PKCS#12 factories
```

Factories copy certificate DER and the chain collection. Inputs after the
leaf are ordered issuers; the terminal root may be omitted. A full leaf-first
list can be passed to `PkiIdentity.of(signer, chain)`. Duplicate certificates,
incorrect order, mismatched issuer names or broken link signatures are rejected.

Construction performs **one actual signing operation** over a fresh,
domain-separated random challenge and verifies it against the leaf public key.
It supports opaque keys and external backends without exporting private key
material. Verification uses the host JCA providers and honors declared PSS
parameters. Backend failures preserve their cause. The key/backend remains
application-owned and must keep a stable key and algorithm; the model does not
close or destroy it. Trust-only PKCS#12 input is not a signing identity.

An identity is not an acceptance decision: expiry, CA constraints, revocation,
hostname and trust policy are handled by validation. Certificates in the identity
chain do **not** become trust anchors. Keep identity and trust inputs separate.

## Explicit trust bundles

```java
TrustBundle trusted = TrustBundle.fromPem(Path.of("trusted-roots.pem"))
    .merge(TrustBundle.fromJks(Path.of("trusted.jks"), password),
           TrustBundle.fromPkcs12(Path.of("trusted.p12"), password));
List<X509Certificate> anchors = trusted.getTrustAnchors();
// Also: TrustBundle.of(rootA, rootB), TrustBundle.fromKeyStore(keyStore).
```

The bundle is immutable: certificate DER and collections are snapshotted,
duplicates are removed by encoded certificate equality, and first encounter
order is preserved. Keystore aliases are read in lexicographic order. The model
represents anchors, not alias metadata, key entries or issuer chains.

JKS/PKCS#12 loaders select only trusted certificate entries, ignoring every
private-key entry and its entire identity chain. Password `char[]` values are
copied and the internal copies cleared after loading; no password is retained.
`of(...)` and PEM input explicitly trust **every supplied certificate**, including
an intentionally trusted intermediate or leaf. Supply an application-selected
anchor set, never an untrusted peer's certificate chain. PEM loaders reject
empty or mixed non-certificate input; an empty programmatic/keystore bundle
establishes no trust.

`CertValidator.trustBundle(...)` and `ChainBuilder.trustBundle(...)` accept this
model. Existing `trustAnchors(...)` and `trustStore(KeyStore)` APIs remain
available, and the Spring loader uses the shared trusted-entry selection.

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
| `signatureAlgorithm(String)` | `SHA256with{RSA,ECDSA}` or `Ed25519` | named override on private-key paths; explicit RSA-PSS via `PkiSigner.rsaPss(...)` |
| `validFrom(Instant)` / `validUntil(Instant)` | now / `validFor` offset | historical dating |

All defaults follow current best practice. Override only when you have a
concrete reason.
