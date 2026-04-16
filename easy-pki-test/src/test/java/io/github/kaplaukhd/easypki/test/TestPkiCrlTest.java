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
package io.github.kaplaukhd.easypki.test;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import io.github.kaplaukhd.easypki.validation.CertValidator;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
import io.github.kaplaukhd.easypki.validation.ValidationError;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import org.junit.jupiter.api.Test;

class TestPkiCrlTest {

    @Test
    void emptyCrlIsReturnedWhenNothingRevoked() throws Exception {
        TestPki pki = TestPki.create().withIntermediateCa().build();

        X509CRL crl = pki.getCrl();

        assertThat(crl.getRevokedCertificates()).isNullOrEmpty();
        // CRL is issued by the effective signer (intermediate when present).
        assertThat(crl.getIssuerX500Principal())
                .isEqualTo(pki.getIntermediateCa().getSubjectX500Principal());
        crl.verify(pki.getIntermediateCa().getPublicKey());
    }

    @Test
    void revokedLeafAppearsInCrlWithReason() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert().subject("CN=bad").build();
        pki.revoke(cert, RevocationReason.KEY_COMPROMISE);

        assertThat(pki.isRevoked(cert)).isTrue();
        X509CRL crl = pki.getCrl();
        var entry = crl.getRevokedCertificate(cert);
        assertThat(entry).isNotNull();
        assertThat(entry.getRevocationReason())
                .isEqualTo(java.security.cert.CRLReason.KEY_COMPROMISE);
    }

    @Test
    void thenRevokeIsConvenienceForBuildThenRevoke() {
        TestPki pki = TestPki.create().build();

        X509Certificate revoked = pki.issueCert()
                .subject("CN=dead")
                .thenRevoke(RevocationReason.CESSATION_OF_OPERATION);

        assertThat(pki.isRevoked(revoked)).isTrue();
        assertThat(pki.getCrl().getRevokedCertificate(revoked)).isNotNull();
    }

    @Test
    void getCrlReflectsSubsequentRevocations() {
        TestPki pki = TestPki.create().build();
        X509Certificate a = pki.issueCert().subject("CN=a").build();
        X509Certificate b = pki.issueCert().subject("CN=b").build();

        X509CRL initial = pki.getCrl();
        assertThat(initial.getRevokedCertificates()).isNullOrEmpty();

        pki.revoke(a, RevocationReason.KEY_COMPROMISE);
        X509CRL afterA = pki.getCrl();
        assertThat(afterA.getRevokedCertificates()).hasSize(1);

        pki.revoke(b, RevocationReason.SUPERSEDED);
        X509CRL afterB = pki.getCrl();
        assertThat(afterB.getRevokedCertificates()).hasSize(2);
    }

    @Test
    void certValidatorWithTestPkiCrlDetectsRevocation() {
        TestPki pki = TestPki.create()
                .withIntermediateCa()
                .build();

        X509Certificate leaf = pki.issueCert()
                .subject("CN=revoked-leaf")
                .thenRevoke(RevocationReason.PRIVILEGE_WITHDRAWN);

        ValidationResult result = CertValidator.of(leaf)
                .chain(pki.getIntermediateCa(), pki.getRootCa())
                .crl(pki.getCrl())
                .validate();

        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.PRIVILEGE_WITHDRAWN);
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code()).isEqualTo(ValidationError.Code.REVOKED));
    }

    @Test
    void rootOnlyPkiCrlIsSignedByRoot() throws Exception {
        TestPki pki = TestPki.create().build();

        X509Certificate leaf = pki.issueCert().subject("CN=leaf").build();
        pki.revoke(leaf, RevocationReason.UNSPECIFIED);

        X509CRL crl = pki.getCrl();
        assertThat(crl.getIssuerX500Principal())
                .isEqualTo(pki.getRootCa().getSubjectX500Principal());
        crl.verify(pki.getRootCa().getPublicKey());
    }
}
