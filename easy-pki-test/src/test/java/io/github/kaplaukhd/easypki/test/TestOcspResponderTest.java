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

import java.security.cert.X509Certificate;

import io.github.kaplaukhd.easypki.validation.CertValidator;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import org.junit.jupiter.api.Test;

class TestOcspResponderTest {

    @Test
    void goodStatusForUnrevokedCert() {
        TestPki pki = TestPki.create().withIntermediateCa().build();
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {

            X509Certificate leaf = pki.issueCert()
                    .subject("CN=good")
                    .ocsp(ocsp.getUrl())
                    .build();

            ValidationResult result = CertValidator.of(leaf)
                    .chain(pki.getIntermediateCa(), pki.getRootCa())
                    .ocsp()
                    .validate();

            assertThat(result.isValid()).isTrue();
            assertThat(result.isRevoked()).isFalse();
            assertThat(ocsp.getRequestCount()).isGreaterThanOrEqualTo(1);
        }
    }

    @Test
    void revokedStatusIsReportedAfterThenRevoke() {
        TestPki pki = TestPki.create().withIntermediateCa().build();
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {

            X509Certificate leaf = pki.issueCert()
                    .subject("CN=revoked")
                    .ocsp(ocsp.getUrl())
                    .thenRevoke(RevocationReason.KEY_COMPROMISE);

            ValidationResult result = CertValidator.of(leaf)
                    .chain(pki.getIntermediateCa(), pki.getRootCa())
                    .ocsp()
                    .validate();

            assertThat(result.isRevoked()).isTrue();
            assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        }
    }

    @Test
    void revocationAfterIssueIsReflectedOnSubsequentQueries() {
        TestPki pki = TestPki.create().withIntermediateCa().build();
        try (TestOcspResponder ocsp = pki.startOcspResponder()) {

            X509Certificate leaf = pki.issueCert()
                    .subject("CN=later-revoked")
                    .ocsp(ocsp.getUrl())
                    .build();

            // First query: GOOD
            ValidationResult first = CertValidator.of(leaf)
                    .chain(pki.getIntermediateCa(), pki.getRootCa())
                    .ocsp()
                    .validate();
            assertThat(first.isRevoked()).isFalse();

            // Revoke and re-query
            pki.revoke(leaf, RevocationReason.CA_COMPROMISE);
            ValidationResult second = CertValidator.of(leaf)
                    .chain(pki.getIntermediateCa(), pki.getRootCa())
                    .ocsp()
                    .validate();
            assertThat(second.isRevoked()).isTrue();
            assertThat(second.getRevokeReason()).isEqualTo(RevocationReason.CA_COMPROMISE);
        }
    }

    @Test
    void responderStopsOnClose() {
        TestPki pki = TestPki.create().build();
        TestOcspResponder ocsp = pki.startOcspResponder();
        String url = ocsp.getUrl();
        ocsp.close();

        // After close, further requests must fail. Use a short timeout so the
        // test doesn't hang if the server somehow stayed up.
        X509Certificate leaf = pki.issueCert().subject("CN=dangling").ocsp(url).build();
        ValidationResult r = CertValidator.of(leaf)
                .chain(pki.getRootCa())
                .ocsp(o -> o.timeout(java.time.Duration.ofSeconds(2)))
                .validate();

        assertThat(r.isRevoked()).isFalse();
        assertThat(r.getErrors()).anySatisfy(e -> {
            // Either OCSP_UNAVAILABLE (tried and failed) or REVOCATION_UNKNOWN is acceptable.
            assertThat(e.code()).isIn(
                    io.github.kaplaukhd.easypki.validation.ValidationError.Code.OCSP_UNAVAILABLE,
                    io.github.kaplaukhd.easypki.validation.ValidationError.Code.REVOCATION_UNKNOWN);
        });
    }
}
