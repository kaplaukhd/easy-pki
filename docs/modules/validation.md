# easy-pki-validation

Production-ready chain validation and revocation checking. Built on top of
`easy-pki-core`.

## Chain-only validation

```java
ValidationResult r = CertValidator.of(leaf)
    .chain(intermediate, root)
    .validate();

r.isValid();            // boolean
r.isExpired();
r.isNotYetValid();
r.isTrusted();
r.getValidationPath(); // ordered: [leaf, intermediate, root]
r.getErrors();          // typed ValidationError list
```

What the validator checks:

- `notBefore`/`notAfter` on every certificate in the path (optionally at a
  historical instant via `.at(Instant)`).
- Issuer DN / subject DN continuity up the chain.
- Each parent public key verifies the child's signature.
- Every cert used as an issuer has `BasicConstraints cA=TRUE`.
- The chain terminates in a self-signed root **or** in one of the configured
  `trustAnchors(...)`. Rogue self-signed roots are rejected when explicit
  anchors are configured.

## Time-travel validation

```java
CertValidator.of(cert)
    .chain(intermediate, root)
    .at(Instant.parse("2030-06-01T00:00:00Z"))
    .validate();
```

Useful for historical audits and certificate-archive tools.

## Revocation: CRL

### Static CRL

```java
X509CRL crl = PkiCrls.fromFile(Path.of("ca.crl"));

CertValidator.of(leaf).chain(intermediate, root)
    .crl(crl)
    .validate();
```

The validator looks up a matching CRL by issuer DN, verifies its signature
against the issuer's public key, and enforces
`thisUpdate`/`nextUpdate` freshness.

### HTTP auto-fetch

```java
CertValidator.of(leaf).chain(intermediate, root)
    .crl(c -> c.autoFetch()
               .cache(Duration.ofMinutes(30))
               .timeout(Duration.ofSeconds(10))
               .proxy("http://proxy.corp:3128"))
    .validate();
```

CRLs are fetched from every URL listed in the certificate's CRL Distribution
Points extension. Only `http://` and `https://` schemes are considered. The
in-memory cache honours `min(configured-TTL, CRL.nextUpdate)`.

### CRL generation

```java
X509CRL crl = PkiCrl.issued()
    .issuer(caCert, caPrivateKey)
    .nextUpdate(Duration.ofHours(24))
    .revoke(leaf1, RevocationReason.KEY_COMPROMISE)
    .revoke(leaf2, RevocationReason.SUPERSEDED)
    .build();

byte[] der  = PkiCrls.toDer(crl);
String pem  = PkiCrls.toPem(crl);
PkiCrls.toFile(crl, Path.of("ca.crl"));
```

## Revocation: OCSP

### With defaults

```java
CertValidator.of(leaf).chain(intermediate, root)
    .ocsp()    // URL from cert's AIA, 10-second timeout, nonce enabled
    .validate();
```

### Tuned

```java
CertValidator.of(leaf).chain(intermediate, root)
    .ocsp(o -> o.url("http://ocsp.corp.internal")     // override AIA URL
                .timeout(Duration.ofSeconds(5))
                .proxy("http://proxy.corp:3128")
                .nonce(true))                         // RFC 6960 nonce
    .validate();
```

The URL override applies **only to the leaf**; intermediates always use their
own AIA extension or skip OCSP.

## OCSP with CRL fallback

```java
CertValidator.of(leaf).chain(intermediate, root)
    .ocspWithCrlFallback()                // OCSP preferred, CRL on failure
    .ocsp(o -> o.timeout(Duration.ofSeconds(5)))
    .crl(c -> c.autoFetch())
    .validate();
```

This is the recommended mode for production: OCSP gives a fresh answer;
CRL is consulted only if OCSP is unavailable. When both are configured,
combination happens automatically — `.ocspWithCrlFallback()` is a
one-line convenience that's equivalent to `.ocsp().crl(c -> c.autoFetch())`.

## Revocation policy

`easy-pki-validation` uses a pragmatic, browser-style policy:

- **The leaf** must be checkable. If no revocation source can produce a
  definitive answer, the result gets a `REVOCATION_UNKNOWN` error.
- **Intermediates** soft-pass when no revocation data is available —
  matching the behaviour of major browsers.

## Automatic chain building

Given a leaf and a pool of intermediates, `ChainBuilder` finds the path to
a trust anchor.

```java
CertChain chain = ChainBuilder.of(leaf)
    .intermediates(intermediatePool)   // Collection<X509Certificate>
    .trustStore(trustKeyStore)         // or .trustAnchors(rootA, rootB)
    .build();                          // throws if no path exists

chain.getLeaf();
chain.getRoot();
chain.getCertificates();  // leaf, ..., root

chain.validate();         // chain-only validation
chain.toValidator()       // attach revocation
    .ocspWithCrlFallback()
    .validate();
```

The algorithm walks upward from the leaf, at each step choosing a candidate
whose subject DN matches *and* whose public key actually verifies the
current certificate's signature — so impostor certificates with colliding
DNs are rejected by construction.

## ValidationError codes

| Code | Meaning |
|---|---|
| `EXPIRED` | Certificate's `notAfter` is in the past |
| `NOT_YET_VALID` | Certificate's `notBefore` is in the future |
| `ISSUER_MISMATCH` | Issuer/subject DN mismatch in the chain |
| `BROKEN_SIGNATURE` | Signature does not verify |
| `NOT_A_CA` | An intermediate lacks `BasicConstraints cA=TRUE` |
| `UNTRUSTED_ROOT` | Chain does not terminate in a trusted anchor |
| `INCOMPLETE_CHAIN` | Chain is empty or missing required certificates |
| `REVOKED` | Reported as revoked by OCSP or CRL |
| `REVOCATION_UNKNOWN` | Revocation status could not be determined |
| `OCSP_UNAVAILABLE` | OCSP responder unreachable or returned error |
| `CRL_UNAVAILABLE` | CRL could not be fetched / parsed / verified |
