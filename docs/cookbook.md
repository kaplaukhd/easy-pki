# Cookbook

Copy-pasteable recipes for the most common tasks.

## Load a trust-anchor-only bundle

```java
Pkcs12Bundle truststore = PkiPkcs12.load(Path.of("truststore.p12"), "changeit");
List<X509Certificate> anchors = truststore.getChain();
```

## Convert PEM to PKCS#12 for a TLS server

```java
X509Certificate leaf  = PkiCertificates.fromFile(Path.of("server.crt"));
PrivateKey      key   = PkiPrivateKeys.fromFile(Path.of("server.key"), "changeit");
List<X509Certificate> chain = PkiCertificates.allFromFile(Path.of("chain.pem"));

// chain.pem is usually intermediate(s); prepend the leaf and save.
List<X509Certificate> aboveLeaf = chain.stream()
    .filter(c -> !c.equals(leaf))
    .toList();

PkiPkcs12.create()
    .certificate(leaf)
    .privateKey(key)
    .chain(aboveLeaf)
    .password("changeit")
    .build()
    .saveTo(Path.of("server.p12"));
```

## Inspect a remote TLS server's cert

```java
try (SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault()
        .createSocket("example.com", 443)) {
    s.startHandshake();
    X509Certificate leaf =
        (X509Certificate) s.getSession().getPeerCertificates()[0];

    PkiCertInfo info = PkiCertInfo.of(leaf);
    System.out.println("Subject:    " + info.getSubject());
    System.out.println("Expires:    " + info.getNotAfter());
    System.out.println("SHA-256:    " + info.getFingerprint(HashAlgorithm.SHA256));
    System.out.println("SANs:       " + info.getSans());
    System.out.println("OCSP:       " + info.getOcspUrls());
}
```

## Issue a client cert for API authentication

```java
IssuedCert apiClient = pki.issueCert()
    .subject("CN=api-client, OU=Services")
    .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
    .validFor(Duration.ofDays(90))
    .issue();

PkiPkcs12.create()
    .certificate(apiClient.certificate())
    .privateKey(apiClient.privateKey())
    .chain(pki.getIntermediateCa(), pki.getRootCa())
    .alias("api-client")
    .password("changeit")
    .build()
    .saveTo(Path.of("api-client.p12"));
```

## Validate a chain offline with a known CRL

```java
X509CRL crl = PkiCrls.fromFile(Path.of("ca.crl"));

ValidationResult r = CertValidator.of(leaf)
    .chain(intermediate, root)
    .crl(crl)
    .validate();
```

## Build a chain from a random pool

```java
CertChain chain = ChainBuilder.of(leaf)
    .intermediates(poolFromDirectory())   // Collection<X509Certificate>
    .trustStore(systemTrustStore)         // java.security.KeyStore
    .build();

// chain-only
chain.validate();

// with revocation
chain.toValidator().ocspWithCrlFallback().validate();
```

## Monitor certificate expiry in a non-Spring app

```java
ApplicationEventPublisher publisher = event -> {
    if (event instanceof CertExpiringEvent e) alert.expiring(e);
    if (event instanceof CertExpiredEvent e)  alert.expired(e);
};

CertificateMonitor monitor = new CertificateMonitor(
    publisher,
    Duration.ofHours(12),   // check interval
    Duration.ofDays(30));   // warn-before
monitor.registerBundle(trustStore, "trust");
monitor.start();

Runtime.getRuntime().addShutdownHook(new Thread(monitor::stop));
```

## Rotate a PKCS#12 password

```java
Pkcs12Bundle old = PkiPkcs12.load(Path.of("keystore.p12"), "old-password");

PkiPkcs12.create()
    .certificate(old.getCertificate())
    .privateKey(old.getPrivateKey())
    .chain(old.getChain().subList(1, old.getChain().size()))
    .alias(old.getAlias())
    .password("new-password")
    .build()
    .saveTo(Path.of("keystore.p12"));
```

## Check revocation status in a background job

```java
@Scheduled(cron = "0 0 */4 * * *")
public void checkRevocation() {
    for (X509Certificate c : certificatesOfInterest) {
        ValidationResult r = validator.newValidator(c)
            .ocspWithCrlFallback()
            .validate();
        if (r.isRevoked()) {
            alertService.page("Certificate " + c.getSubjectX500Principal()
                              + " was revoked: " + r.getRevokeReason());
        }
    }
}
```

## Produce an OCSP-enabled test fixture

```java
@ExtendWith(EasyPkiExtension.class)
class TlsHandshakeTest {

    @InjectTestPki TestPki pki;

    @Test
    void rejectsRevokedClient() {
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {
            X509Certificate revoked = pki.issueCert()
                .subject("CN=rev-client")
                .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
                .ocsp(ocsp.getUrl())
                .thenRevoke(RevocationReason.KEY_COMPROMISE);

            ValidationResult r = CertValidator.of(revoked)
                .chain(pki.getIntermediateCa(), pki.getRootCa())
                .ocsp()
                .validate();

            assertThat(r.isRevoked()).isTrue();
            assertThat(r.getRevokeReason())
                .isEqualTo(RevocationReason.KEY_COMPROMISE);
        }
    }
}
```
