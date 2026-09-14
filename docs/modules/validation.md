# easy-pki-validation

Production-ready chain validation and revocation checking. Built on top of
`easy-pki-core`.

## Chain-only validation

```java
ValidationResult r = CertValidator.of(leaf)
    .chain(intermediate, root)
    .trustAnchors(root)     // root configured by the application
    .validate();

r.isValid();            // boolean
r.isExpired();
r.isNotYetValid();
r.isTrusted();          // linkage to an explicit anchor; not the overall decision
r.getValidationPath(); // ordered: [leaf, intermediate, root]
r.getErrors();          // typed ValidationError list
```

Configure trust independently of the peer's chain. `trustAnchors(...)` must
contain certificates approved by the application, such as its configured CA.
A self-signed certificate or a root supplied only through `chain(...)` does
not establish trust. With no anchors configured, validation fails with
`UNTRUSTED_ROOT`.

`CertValidator` validates the supplied ordered path: the subject certificate,
then its issuer, and so on toward a configured anchor. It does not reorder
the input or search alternative intermediates. Use `ChainBuilder` when you
have an unordered pool or cross-signed alternatives. The validator does not
truncate a supplied chain at an earlier anchor: when trusting an intermediate,
end the chain there (or omit that anchor), rather than supplying its root above it.

The PKIX path validator checks certificate validity at the evaluation time,
issuer names and signatures, CA basic constraints and path length, issuer
KeyUsage, name constraints, certificate policies, supported critical
extensions and applicable JCA algorithm constraints. It does not infer a TLS
hostname or application purpose from this chain-only API.

A trust anchor may be a root or an explicitly trusted intermediate. When
the supplied chain ends with that anchor, the anchor is removed from the
PKIX path. Its own expiry, self-signature and extensions are not checked:
the application has already chosen it as a source of trust. This does not
skip validation of certificates below the anchor.

`isTrusted()` means that the terminal certificate links to an explicitly
configured anchor. It may be true even when another PKIX or revocation
check fails. Use `isValid()` for the overall acceptance decision.
`getValidationPath()` preserves the subject and supplied chain, including a
terminal anchor only when it was supplied. An omitted anchor is not appended
to this result.

## Time-travel validation

```java
CertValidator.of(cert)
    .chain(intermediate, root)
    .trustAnchors(root)
    .at(Instant.parse("2030-06-01T00:00:00Z"))
    .validate();
```

This controls the PKIX evaluation time. It does not introduce archival OCSP
evidence or change the existing CRL/OCSP freshness and fallback behavior.

## Revocation: CRL

### Static CRL

```java
X509CRL crl = PkiCrls.fromFile(Path.of("ca.crl"));

CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
    .crl(crl)
    .validate();
```

The validator looks up a matching CRL by issuer DN, verifies its signature
against the issuer's public key, and enforces
`thisUpdate`/`nextUpdate` freshness.

### HTTP auto-fetch

```java
CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
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
    .trustAnchors(root)
    .ocsp()    // URL from cert's AIA, 10-second timeout, nonce enabled
    .validate();
```

### Tuned

```java
CertValidator.of(leaf).chain(intermediate, root)
    .trustAnchors(root)
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
    .trustAnchors(root)
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

Given a leaf, an unordered pool of intermediates and explicitly configured
trust, `ChainBuilder` uses the JCA PKIX builder to find a valid path to an
anchor. The intermediate pool supplies candidates, never trust.

```java
CertChain chain = ChainBuilder.of(leaf)
    .intermediates(intermediatePool)   // Collection<X509Certificate>
    .trustStore(trustKeyStore)         // or .trustAnchors(rootA, rootB)
    .build();                          // throws if no path exists

chain.getLeaf();
chain.getRoot();          // selected anchor, which may be a trusted intermediate
chain.getCertificates();  // leaf, ..., selected anchor, included once

chain.validate();         // chain-only validation
chain.toValidator()       // attach revocation
    .ocspWithCrlFallback()
    .validate();
```

The builder can choose another cross-signed branch when one candidate path
is invalid. Input order does not determine whether a valid path can be
found; when several paths are valid, no particular selected path is
guaranteed. The resulting `CertChain` retains the selected anchor for
`validate()` and `toValidator()`. Its certificate list includes that anchor
once, unlike a direct `CertValidator` result whose input omitted the anchor.

PKIX chain validation and construction do not enable the JDK's revocation
checker. Existing opt-in CRL and OCSP handling remains separate; it runs
only after the supplied path passes validation.

## ValidationError codes

| Code | Meaning |
|---|---|
| `EXPIRED` | Certificate's `notAfter` is in the past |
| `NOT_YET_VALID` | Certificate's `notBefore` is in the future |
| `ISSUER_MISMATCH` | Issuer/subject DN mismatch in the chain |
| `BROKEN_SIGNATURE` | Signature does not verify |
| `NOT_A_CA` | An intermediate lacks `BasicConstraints cA=TRUE` |
| `UNTRUSTED_ROOT` | No explicit anchor is configured or the chain does not link to one |
| `INCOMPLETE_CHAIN` | Chain is empty or missing required certificates |
| `PATH_TOO_LONG` | The path exceeds a CA's basic constraints path length |
| `INVALID_KEY_USAGE` | A certificate's key usage does not permit its role in the path |
| `INVALID_NAME` | A certificate violates name constraints |
| `UNRECOGNIZED_CRITICAL_EXTENSION` | A critical extension cannot be processed |
| `ALGORITHM_CONSTRAINED` | The JCA algorithm policy rejects a key or signature algorithm |
| `INVALID_POLICY` | Certificate policy processing failed |
| `PKIX_VALIDATION_FAILED` | PKIX rejected the path for another reason |
| `REVOKED` | Reported as revoked by OCSP or CRL |
| `REVOCATION_UNKNOWN` | Revocation status could not be determined |
| `OCSP_UNAVAILABLE` | OCSP responder unreachable or returned error |
| `CRL_UNAVAILABLE` | CRL could not be fetched / parsed / verified |
