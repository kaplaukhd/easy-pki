# Migration from raw BouncyCastle

Side-by-side recipes for replacing common BouncyCastle patterns with
`easy-pki`.

## Migrating from earlier easy-pki snapshots

### DN, certificate identity, encrypted PEM and CRL support

`subject(String)` now uses `X500Principal` parsing and ordering. For example,
`CN=host,O=Acme,C=US` reads back in that order through JCA, instead of the
reversed order emitted by earlier snapshots. Fluent `DnBuilder` uses the same
display order, with literal escaped values. Multi-valued RDNs are supported
in string/principal input; the fluent helper adds one RDN per call. Use
JCA keywords or numeric OIDs instead of BC-specific keyword aliases. To
preserve an existing subject exactly during renewal, pass
`.subject(existingCertificate.getSubjectX500Principal())`. Existing encoded
certificates and automatically copied issuer names are not rewritten.

`PkiCertInfo.isSelfIssued()` checks name equality. `isSelfSigned()` now also
verifies the signature with the certificate's own key; a key-rollover
certificate signed by a different key is no longer reported as self-signed.
Neither method checks trust or expiry. Certificate and CRL AKI now copy the
issuer's SKI when present, preserving the key-identifier-only form; absent
SKI falls back to the public-key identifier calculation.

Encrypted PEM writing now explicitly selects PBKDF2-HMAC-SHA-256 with 600,000
iterations and AES-256-CBC. This costs more CPU than the former BC defaults.
Use immutable `PemEncryptionOptions` to tune iteration count and choose
HMAC-SHA-256 or HMAC-SHA-512. Existing PEM formats remain readable. New
`char[]` overloads leave caller arrays unchanged, clear temporary library
copies on success/failure and retain no password in the options. Clear your
own array after use; String and provider/JVM copies cannot be guaranteed
erased. See [private-key I/O](modules/core.md#private-keys).

Only complete direct unpartitioned CRLs are now interpreted. Delta CRLs,
any issuing distribution point, indirect entries and critical CRL/entry
extensions produce `UNSUPPORTED_CRL`; they can no longer establish GOOD.
Fallback to a supported candidate remains possible, with the rejected
candidate reported in warnings. Without such recovery the result is invalid.
The [validation guide](modules/validation.md) defines the supported boundary.

The [Spring testing example](modules/testing.md#testing-a-spring-boot-app-with-autoconfiguremockmvc)
now uses one class-scoped CA and truststore, a single-argument static
`DynamicPropertySource`, explicit filter registration and context cleanup.
It is included directly from its compiled MockMvc test.

### PKCS#12, serial numbers and Bouncy Castle

Trust-only `Pkcs12Bundle` exports now retain every certificate, each under a
separate trusted-entry alias. New bundles use the primary alias, then
`<alias>-2`, `<alias>-3`, and so on. Loaded trust-only stores preserve all
provider-reported aliases when re-exported and expose certificates in
lexicographic alias order; their primary entry is now the first alias in
that order. A trust-only `getChain()` is a flat collection that can contain
unrelated roots, not an issuer chain. Identity bundles keep their existing
key-entry and ordered-chain behavior. See the
[PKCS#12 guide](modules/core.md#pkcs12) for details, including case normalization.

Both certificate builders now require explicit serials in `1..2^159-1`.
Values at or above `2^159` fail immediately with `IllegalArgumentException`;
zero and negative values remain invalid. Generated serials use the same
range, leaving room for the DER sign bit within the 20-octet value limit.
Existing certificates are still readable; these constraints apply to issuance.

The tested Bouncy Castle dependencies are upgraded together from 1.78.1 to
[1.86](https://www.bouncycastle.org/resources/new-release-bouncy-castle-java-1-86/):
`bcprov-jdk18on`, `bcpkix-jdk18on` and transitive `bcutil-jdk18on`.
Applications overriding dependency versions must keep these artifacts aligned.
Regression fixtures cover certificate PEM/DER, encrypted private-key PEM and
identity PKCS#12 material produced before the upgrade. The library still uses
JCA types and does not register a global provider; new algorithms in BC are not
automatically exposed by easy-pki's builders.

This development snapshot has no API freeze. Installation examples use a
local `1.0.0-SNAPSHOT` build; use published coordinates only after verifying
their availability in Maven Central.

### Trust, path validation and revocation

The unreleased validation changes are **breaking behavior changes**. A
self-signed chain previously accepted without an explicit trust anchor now
fails with `UNTRUSTED_ROOT`. Configure anchors from application-controlled
trust material, separately from certificates supplied by a peer:

```java
ValidationResult result = CertValidator.of(leaf)
    .chain(peerIntermediates)             // ordered issuer-to-anchor path
    .trustAnchors(applicationTrustedCa)    // independently configured trust
    .validate();
```

Do not migrate by automatically trusting the last certificate received from
the peer. In tests, use `.trustAnchors(pki.getTrustAnchors())`; the Spring
facade obtains anchors from its configured trust store or custom bean.
`ValidationMode.NONE` disables revocation checks, not trust requirements.

`CertValidator` now delegates the ordered path to PKIX. Previously accepted
paths may be rejected for path length, issuer KeyUsage, name constraints,
unrecognized critical extensions, algorithm constraints or certificate
policies. A configured terminal trust anchor is outside the PKIX path:
its own expiry, self-signature and extensions are not validated. An
explicitly trusted intermediate can also terminate a path.

`isTrusted()` reports linkage to an explicit anchor; use `isValid()` to
decide whether all configured checks passed. `getValidationPath()` keeps
the subject and supplied chain, so it does not append an anchor omitted
from the input.

Use `ChainBuilder` for an unordered intermediate pool. It now performs PKIX
path building and can select a valid cross-signed alternative when another
branch fails. Its `CertChain` includes the selected anchor exactly once and
preserves that trust for `validate()` and `toValidator()`. Configured
revocation checks run only after the supplied path has passed validation.

Revocation now uses the actual PKIX-selected anchor internally, so omitting
the anchor from `chain(...)` no longer skips the final leaf or intermediate.
Trust anchors themselves remain exempt. An intermediate with no source
retains the existing acceptance policy, now with a warning; exhausted
attempts and confirmed revocations remain failures.

Failed OCSP/CRL attempts that recover through a definitive fallback move
from `getErrors()` to `getWarnings()`. Log both lists if you need attempt
diagnostics, and continue using `isValid()` for the final decision. A failed
first CRL distribution point no longer cancels a valid later result.

OCSP freshness is checked even when nonce is disabled. The defaults are
five minutes of clock skew and a 24-hour maximum age without `nextUpdate`,
configurable through `OcspConfig.clockSkew(...)` and `maxResponseAge(...)`.
`.at(...)` also controls OCSP freshness; a present-day response is not
automatically suitable for a historical check. See the
[validation guide](modules/validation.md) for precise boundary rules.

The Spring starter's filter is now disabled for automatic servlet
registration. Enable protection by inserting its bean into your
`SecurityFilterChain`, or explicitly provide its servlet registration.
The starter now loads every trusted certificate entry from a PKCS#12
truststore. A private-key entry's identity chain no longer establishes
trust: import each intended CA as a trusted certificate entry instead.
An empty or key-only truststore fails configuration clearly. The existing
key-store loader and custom named trust-store beans keep their contracts.
See the [Spring guide](modules/spring-boot.md) for examples.

## Generate a 2048-bit RSA key pair

=== "BouncyCastle"

    ```java
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
    kpg.initialize(new RSAKeyGenParameterSpec(
        2048, RSAKeyGenParameterSpec.F4));
    KeyPair keys = kpg.generateKeyPair();
    ```

=== "easy-pki"

    ```java
    KeyPair keys = PkiKeys.rsa(2048);
    ```

## Generate a P-256 EC key pair

=== "BouncyCastle"

    ```java
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    KeyPair keys = kpg.generateKeyPair();
    ```

=== "easy-pki"

    ```java
    KeyPair keys = PkiKeys.ec(Curve.P_256);
    ```

## Self-signed root CA

=== "BouncyCastle"

    ```java
    X500Name subject = new X500NameBuilder()
        .addRDN(BCStyle.CN, "Root")
        .addRDN(BCStyle.O, "Acme")
        .build();

    SecureRandom random = new SecureRandom();
    BigInteger serial;
    do {
        serial = new BigInteger(159, random);
    } while (serial.signum() == 0);
    Date notBefore = new Date();
    Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(3650)));

    X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
        subject, serial, notBefore, notAfter, subject, keys.getPublic());

    cb.addExtension(Extension.basicConstraints, true,
        new BasicConstraints(true));
    cb.addExtension(Extension.keyUsage, true,
        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    cb.addExtension(Extension.subjectKeyIdentifier, false,
        extUtils.createSubjectKeyIdentifier(keys.getPublic()));
    cb.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(keys.getPublic()));

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .build(keys.getPrivate());

    X509CertificateHolder holder = cb.build(signer);
    X509Certificate cert = new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(holder);
    ```

=== "easy-pki"

    ```java
    X509Certificate cert = PkiCertificate.selfSigned()
        .subject("CN=Root, O=Acme")
        .keyPair(keys)
        .validFor(Duration.ofDays(3650))
        .isCA(true)
        .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
        .build();
    ```

## Issuer-signed leaf with SAN and OCSP

=== "BouncyCastle"

    ```java
    X500Name subject = new X500NameBuilder()
        .addRDN(BCStyle.CN, "api.example.com")
        .build();

    SecureRandom random = new SecureRandom();
    BigInteger serial;
    do {
        serial = new BigInteger(159, random);
    } while (serial.signum() == 0);

    X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
        new JcaX509CertificateHolder(issuerCert).getSubject(),
        serial,
        new Date(),
        Date.from(Instant.now().plus(Duration.ofDays(365))),
        subject,
        leafKeys.getPublic());

    GeneralName[] names = {
        new GeneralName(GeneralName.dNSName,  "api.example.com"),
        new GeneralName(GeneralName.dNSName,  "*.api.example.com"),
        new GeneralName(GeneralName.iPAddress, "10.0.0.1"),
    };
    cb.addExtension(Extension.subjectAlternativeName, false,
        new GeneralNames(names));

    AccessDescription ocsp = new AccessDescription(
        AccessDescription.id_ad_ocsp,
        new GeneralName(GeneralName.uniformResourceIdentifier,
                        "http://ocsp.example.org"));
    cb.addExtension(Extension.authorityInfoAccess, false,
        AuthorityInformationAccess.getInstance(
            new DERSequence(new AccessDescription[]{ocsp})));

    // + basic constraints, KU, EKU, SKI, AKI, signer, converter …
    ```

=== "easy-pki"

    ```java
    X509Certificate cert = PkiCertificate.signed()
        .subject("CN=api.example.com")
        .publicKey(leafKeys.getPublic())
        .issuer(issuerCert, issuerKey)
        .validFor(Duration.ofDays(365))
        .san(s -> s.dns("api.example.com")
                   .dns("*.api.example.com")
                   .ip("10.0.0.1"))
        .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
        .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
        .ocsp("http://ocsp.example.org")
        .build();
    ```

## Read a PEM certificate

=== "BouncyCastle"

    ```java
    try (PEMParser p = new PEMParser(new StringReader(pem))) {
        Object obj = p.readObject();
        X509CertificateHolder h = (X509CertificateHolder) obj;
        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(h);
    }
    ```

=== "easy-pki"

    ```java
    X509Certificate cert = PkiCertificates.fromPem(pem);
    ```

## Write an encrypted PKCS#8 private key

=== "BouncyCastle"

    ```java
    OutputEncryptor enc = new JceOpenSSLPKCS8EncryptorBuilder(
            PKCS8Generator.AES_256_CBC)
        .setProvider("BC")
        .setPassword("changeit".toCharArray())
        .build();

    try (JcaPEMWriter w = new JcaPEMWriter(writer)) {
        w.writeObject(new JcaPKCS8Generator(privateKey, enc));
    }
    ```

=== "easy-pki"

    ```java
    String pem = PkiPrivateKeys.toPem(privateKey, "changeit");
    ```

## Generate a CRL

=== "BouncyCastle"

    ```java
    X509v2CRLBuilder cb = new X509v2CRLBuilder(
        new JcaX509CertificateHolder(caCert).getSubject(),
        new Date());
    cb.setNextUpdate(Date.from(Instant.now().plus(Duration.ofHours(24))));
    cb.addCRLEntry(leaf.getSerialNumber(), new Date(),
        CRLReason.keyCompromise);

    JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
    cb.addExtension(Extension.authorityKeyIdentifier, false,
        new AuthorityKeyIdentifier(ext.createAuthorityKeyIdentifier(caCert).getKeyIdentifierOctets()));
    cb.addExtension(Extension.cRLNumber, false,
        new CRLNumber(new BigInteger(128, new SecureRandom())));

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .build(caKey);
    X509CRLHolder holder = cb.build(signer);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509CRL crl = (X509CRL) cf.generateCRL(
        new ByteArrayInputStream(holder.getEncoded()));
    ```

=== "easy-pki"

    ```java
    X509CRL crl = PkiCrl.issued()
        .issuer(caCert, caKey)
        .nextUpdate(Duration.ofHours(24))
        .revoke(leaf, RevocationReason.KEY_COMPROMISE)
        .build();
    ```

## Build an OCSP request

=== "BouncyCastle"

    ```java
    DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().build();
    CertificateID id = new CertificateID(
        dcp.get(CertificateID.HASH_SHA1),
        new JcaX509CertificateHolder(issuer),
        subjectCert.getSerialNumber());

    OCSPReqBuilder rb = new OCSPReqBuilder();
    rb.addRequest(id);
    // + nonce, signing, serialisation, HTTP POST, response parsing …
    ```

=== "easy-pki"

    ```java
    // Usually you don't need to construct the request yourself —
    // let the validator handle it:
    CertValidator.of(subjectCert)
        .chain(issuer)
        .trustAnchors(issuer) // issuer explicitly trusted by the application
        .ocsp()
        .validate();
    ```

## What to keep in mind

- `easy-pki` never registers BouncyCastle as a global JCA provider. If
  your application relies on that side effect, register it yourself.
- All builders return standard JCA types (`X509Certificate`,
  `X509CRL`, `PrivateKey`, `KeyStore`-compatible PKCS#12 bytes). You can
  always drop back to lower-level BouncyCastle or `java.security` APIs.
- Defaults are opinionated (SHA-256, random nonzero serials of at most 159 bits, RSA 2048
  minimum, AES-256-CBC PKCS#8). Override only when you need to.
