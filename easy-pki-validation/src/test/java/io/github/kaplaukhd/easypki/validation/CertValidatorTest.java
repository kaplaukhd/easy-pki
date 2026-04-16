/*
 * Copyright 2026 kaplaukhd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.kaplaukhd.easypki.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertValidatorTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair intermediateKeys;
    private X509Certificate intermediate;
    private KeyPair leafKeys;
    private X509Certificate leaf;

    @BeforeEach
    void buildHierarchy() {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Test Root")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(3650))
                .isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        intermediateKeys = PkiKeys.rsa(2048);
        intermediate = PkiCertificate.signed()
                .subject("CN=Test Intermediate")
                .publicKey(intermediateKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825))
                .pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .build();
    }

    @Test
    void validChainPasses() {
        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
        assertThat(result.isExpired()).isFalse();
        assertThat(result.isNotYetValid()).isFalse();
        assertThat(result.getErrors()).isEmpty();
        assertThat(result.getValidationPath())
                .containsExactly(leaf, intermediate, root);
    }

    @Test
    void detectsExpiredCertificate() {
        KeyPair freshLeafKeys = PkiKeys.rsa(2048);
        X509Certificate expired = PkiCertificate.signed()
                .subject("CN=expired")
                .publicKey(freshLeafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFrom(Instant.now().minus(Duration.ofDays(60)))
                .validUntil(Instant.now().minus(Duration.ofDays(1)))
                .build();

        ValidationResult result = CertValidator.of(expired)
                .chain(intermediate, root)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isExpired()).isTrue();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code()).isEqualTo(ValidationError.Code.EXPIRED));
    }

    @Test
    void detectsNotYetValidCertificate() {
        KeyPair freshLeafKeys = PkiKeys.rsa(2048);
        X509Certificate future = PkiCertificate.signed()
                .subject("CN=future")
                .publicKey(freshLeafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFrom(Instant.now().plus(Duration.ofDays(30)))
                .validUntil(Instant.now().plus(Duration.ofDays(60)))
                .build();

        ValidationResult result = CertValidator.of(future)
                .chain(intermediate, root)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isNotYetValid()).isTrue();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code()).isEqualTo(ValidationError.Code.NOT_YET_VALID));
    }

    @Test
    void historicalEvaluationAccepsPastExpiredCert() {
        // Build an independent backdated hierarchy so the whole chain was
        // valid at the historical instant.
        Instant historicalPoint = Instant.now().minus(Duration.ofDays(365));

        KeyPair oldRootKeys = PkiKeys.rsa(2048);
        X509Certificate oldRoot = PkiCertificate.selfSigned()
                .subject("CN=Old Root").keyPair(oldRootKeys)
                .validFrom(historicalPoint.minus(Duration.ofDays(60)))
                .validUntil(historicalPoint.plus(Duration.ofDays(365)))
                .isCA(true).build();

        KeyPair oldLeafKeys = PkiKeys.rsa(2048);
        X509Certificate oldLeaf = PkiCertificate.signed()
                .subject("CN=historical")
                .publicKey(oldLeafKeys.getPublic())
                .issuer(oldRoot, oldRootKeys.getPrivate())
                .validFrom(historicalPoint.minus(Duration.ofDays(30)))
                .validUntil(historicalPoint.plus(Duration.ofDays(30)))
                .build();

        ValidationResult atPast = CertValidator.of(oldLeaf)
                .chain(oldRoot)
                .at(historicalPoint)
                .validate();
        assertThat(atPast.isValid()).isTrue();
        assertThat(atPast.isExpired()).isFalse();

        // Same certificate evaluated "now" is clearly expired.
        ValidationResult atNow = CertValidator.of(oldLeaf)
                .chain(oldRoot)
                .validate();
        assertThat(atNow.isValid()).isFalse();
        assertThat(atNow.isExpired()).isTrue();
    }

    @Test
    void brokenSignatureIsDetected() throws Exception {
        // Tamper: sign a leaf with keys that don't match the declared intermediate.
        KeyPair attackerKeys = PkiKeys.rsa(2048);
        X509Certificate fakeIntermediate = PkiCertificate.signed()
                .subject(intermediate.getSubjectX500Principal().getName()) // same DN
                .publicKey(attackerKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .pathLength(0)
                .build();
        KeyPair fakeLeafKeys = PkiKeys.rsa(2048);
        X509Certificate leafSignedByAttacker = PkiCertificate.signed()
                .subject("CN=spoof")
                .publicKey(fakeLeafKeys.getPublic())
                .issuer(fakeIntermediate, attackerKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        // Present the REAL intermediate in the chain — mismatch with who actually signed.
        ValidationResult result = CertValidator.of(leafSignedByAttacker)
                .chain(intermediate, root)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.BROKEN_SIGNATURE));
    }

    @Test
    void issuerMismatchDetected() {
        // Build a separate, unrelated root whose subject differs from 'intermediate.issuer'.
        KeyPair otherRootKeys = PkiKeys.rsa(2048);
        X509Certificate otherRoot = PkiCertificate.selfSigned()
                .subject("CN=Unrelated Root")
                .keyPair(otherRootKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, otherRoot) // wrong root after intermediate
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.ISSUER_MISMATCH));
    }

    @Test
    void nonCaUsedAsIssuerIsDetected() {
        // Leaf pretending to be an intermediate (no BasicConstraints CA=TRUE).
        KeyPair pseudoCaKeys = PkiKeys.rsa(2048);
        X509Certificate pseudoCa = PkiCertificate.signed()
                .subject("CN=pseudo")
                .publicKey(pseudoCaKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                // no .isCA(true), no .pathLength(...)
                .build();

        KeyPair belowKeys = PkiKeys.rsa(2048);
        X509Certificate leafBelowPseudo = PkiCertificate.signed()
                .subject("CN=below")
                .publicKey(belowKeys.getPublic())
                .issuer(pseudoCa, pseudoCaKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        ValidationResult result = CertValidator.of(leafBelowPseudo)
                .chain(pseudoCa, root)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.NOT_A_CA));
    }

    @Test
    void chainWithoutRootRequiresExplicitTrustAnchor() {
        ValidationResult untrusted = CertValidator.of(leaf)
                .chain(intermediate)                // no root, no anchors
                .validate();

        assertThat(untrusted.isValid()).isFalse();
        assertThat(untrusted.isTrusted()).isFalse();
        assertThat(untrusted.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.UNTRUSTED_ROOT));

        // Same chain, now with explicit trust anchor:
        ValidationResult trusted = CertValidator.of(leaf)
                .chain(intermediate)
                .trustAnchors(root)
                .validate();

        assertThat(trusted.isValid()).isTrue();
        assertThat(trusted.isTrusted()).isTrue();
    }

    @Test
    void selfSignedRootNotInTrustStoreIsRejected() {
        KeyPair otherKeys = PkiKeys.rsa(2048);
        X509Certificate otherRoot = PkiCertificate.selfSigned()
                .subject("CN=Rogue Root")
                .keyPair(otherKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true).build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, otherRoot)
                .trustAnchors(root)         // only 'root' is trusted; otherRoot is rogue
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.UNTRUSTED_ROOT));
    }

    @Test
    void directlyValidatingASelfSignedRootWorks() {
        ValidationResult result = CertValidator.of(root).validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
        assertThat(result.getValidationPath()).containsExactly(root);
    }
}
