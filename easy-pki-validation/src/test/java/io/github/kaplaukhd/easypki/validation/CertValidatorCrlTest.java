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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertValidatorCrlTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair intermediateKeys;
    private X509Certificate intermediate;
    private KeyPair leafKeys;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Root").keyPair(rootKeys)
                .validFor(Duration.ofDays(3650)).isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();

        intermediateKeys = PkiKeys.rsa(2048);
        intermediate = PkiCertificate.signed()
                .subject("CN=Intermediate").publicKey(intermediateKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825)).pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();

        leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf").publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365)).build();
    }

    @Test
    void nonRevokedCertPassesWithCrl() {
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(leafCrl, intermediateCrl)
                .validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isRevoked()).isFalse();
    }

    @Test
    void revokedLeafIsDetected() {
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.KEY_COMPROMISE)
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(leafCrl, intermediateCrl)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(result.getRevokeTime()).isNotNull();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code()).isEqualTo(ValidationError.Code.REVOKED));
    }

    @Test
    void revokedIntermediateIsDetected() {
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(intermediate, RevocationReason.CA_COMPROMISE)
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(leafCrl, intermediateCrl)
                .validate();

        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.CA_COMPROMISE);
    }

    @Test
    void missingCrlForCertProducesRevocationUnknown() {
        // Provide CRL for intermediate only, none for leaf's issuer.
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(intermediateCrl)
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
    }

    @Test
    void expiredCrlIsRejected() {
        Instant past = Instant.now().minus(Duration.ofDays(30));
        X509CRL staleCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .thisUpdate(past)
                .nextUpdate(past.plus(Duration.ofDays(1))) // long expired
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(staleCrl, intermediateCrl)
                .validate();

        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.CRL_UNAVAILABLE))
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
    }

    @Test
    void crlSignedByWrongKeyIsRejected() {
        KeyPair imposterKeys = PkiKeys.rsa(2048);
        X509Certificate imposterCa = PkiCertificate.selfSigned()
                .subject(intermediate.getSubjectX500Principal().getName()) // same DN
                .keyPair(imposterKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        // CRL issued by imposter but with same issuer DN as real intermediate.
        X509CRL fakeCrl = PkiCrl.issued()
                .issuer(imposterCa, imposterKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.KEY_COMPROMISE)
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(fakeCrl, intermediateCrl)
                .validate();

        // The fake CRL must NOT revoke the cert — signature doesn't verify against
        // the real intermediate's public key.
        assertThat(result.isRevoked()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.CRL_UNAVAILABLE));
    }

    @Test
    void crlCheckOptInOnly() {
        // Same revoked leaf as above, but validator is not told to check CRLs → passes.
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.KEY_COMPROMISE)
                .build();

        // No .crl(...) call → no revocation checking.
        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isRevoked()).isFalse();

        // The CRL exists but is simply not consulted here.
        assertThat(leafCrl.getRevokedCertificate(leaf)).isNotNull();
    }
}
