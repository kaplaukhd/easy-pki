# Bouncy Castle 1.78.1 compatibility fixtures

These are synthetic test identities generated solely for this repository. All
private keys and their password are public test data; never use them as real
identities or trust anchors. The password is `synthetic-fixture-password`.

The files were generated on 2026-10-08 from an isolated `git archive` of easy-pki
commit `36c6475783609b5ae0092b4a7100aeff8dd4838f`, using Amazon Corretto
`17.0.15+6-LTS` and cached `bcprov-jdk18on`, `bcpkix-jdk18on`, and `bcutil-jdk18on`
JARs, all version **1.78.1**. The archived core module was compiled offline before
generation. The generator checked both
`new BouncyCastleProvider().getVersionStr().equals("1.7801")` and
`getInfo().equals("BouncyCastle Security Provider v1.78.1")`; the provider uses
`1.7801` as its numeric version string for release 1.78.1.

| Files | Generated material |
| --- | --- |
| `rsa-root.pem`, `rsa-root.der` | RSA 2048 self-signed CA, SHA256withRSA, serial 178101 |
| `ec-root.pem`, `ec-root.der` | P-256 self-signed CA, SHA256withECDSA, serial 178102 |
| `rsa-root-encrypted-key.pem` | RSA CA private key, encrypted PKCS#8 PEM |
| `ec-root-encrypted-key.pem` | EC CA private key, encrypted PKCS#8 PEM |
| `rsa-identity.p12` | RSA 2048 leaf private key and ordered leaf/RSA-root chain; alias `synthetic-identity`; leaf serial 178103 |

Generation used `PkiKeys.rsa(2048)` and `PkiKeys.ec(Curve.P_256)`, then
`PkiCertificate.selfSigned()` for the roots and `PkiCertificate.signed()` for the
leaf. All certificates have fixed validity from `2024-01-01T00:00:00Z` to
`2044-01-01T00:00:00Z` and the serial numbers above. Root subjects are
`CN=Synthetic BC 1.78.1 RSA Root` and `CN=Synthetic BC 1.78.1 EC Root`; both have
CA basic constraints and `KEY_CERT_SIGN`/`CRL_SIGN` key usages. The leaf subject
is `CN=Synthetic BC 1.78.1 Identity`, with `DIGITAL_SIGNATURE` and `TLS_CLIENT`
extended key usage.

PEM/DER were written with `PkiCertificates.toFile()`/`toDer()`. Encrypted keys
were written with `PkiPrivateKeys.toFile(key, path, password)` using the old
PBES2/AES-256-CBC writer. The identity was saved with
`PkiPkcs12.create().certificate(leaf).privateKey(leafKey).chain(rsaRoot)` and the
alias/password above. That API uses the JDK's default PKCS#12 implementation;
the contained certificates and keys were created with the old dependency.

Key generation, ECDSA signatures, encryption salts/IVs, and PKCS#12 metadata are
randomized. Preserve these files as frozen artifacts; do not regenerate them
with the current dependency during tests. The tests read both certificate
encodings, verify signatures through JCA, decrypt both encrypted key types,
and prove that the imported keys still match their certificates. They use fixed
certificate metadata rather than the wall clock, so fixture expiry does not
make the compatibility checks fail.
