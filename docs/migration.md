# Migration from raw BouncyCastle

Side-by-side recipes for replacing common BouncyCastle patterns with
`easy-pki`.

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

    BigInteger serial = new BigInteger(160, new SecureRandom());
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

    X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
        new JcaX509CertificateHolder(issuerCert).getSubject(),
        new BigInteger(160, new SecureRandom()),
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
        ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));
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
        .ocsp()
        .validate();
    ```

## What to keep in mind

- `easy-pki` never registers BouncyCastle as a global JCA provider. If
  your application relies on that side effect, register it yourself.
- All builders return standard JCA types (`X509Certificate`,
  `X509CRL`, `PrivateKey`, `KeyStore`-compatible PKCS#12 bytes). You can
  always drop back to lower-level BouncyCastle or `java.security` APIs.
- Defaults are opinionated (SHA-256, random 20-byte serials, RSA 2048
  minimum, AES-256-CBC PKCS#8). Override only when you need to.
