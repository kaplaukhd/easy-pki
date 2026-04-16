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
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertInfo;
import io.github.kaplaukhd.easypki.SubjectAlternativeName;
import io.github.kaplaukhd.easypki.validation.CertValidator;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import org.junit.jupiter.api.Test;

class TestPkiTest {

    @Test
    void minimalPkiWithIntermediate_signsAndValidatesLeaf() throws Exception {
        TestPki pki = TestPki.create()
                .withRootCa("CN=Acme Root")
                .withIntermediateCa("CN=Acme Issuing")
                .build();

        X509Certificate leaf = pki.issueCert()
                .subject("CN=api.example.org")
                .build();

        // Self-consistency: leaf is signed by the intermediate.
        leaf.verify(pki.getIntermediateCa().getPublicKey());
        assertThat(leaf.getIssuerX500Principal())
                .isEqualTo(pki.getIntermediateCa().getSubjectX500Principal());

        // Full chain validates cleanly.
        ValidationResult result = CertValidator.of(leaf)
                .chain(pki.getIntermediateCa(), pki.getRootCa())
                .validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
    }

    @Test
    void withoutIntermediate_rootSignsLeafDirectly() throws Exception {
        TestPki pki = TestPki.create()
                .withRootCa("CN=Flat Root")
                .build();

        assertThat(pki.hasIntermediate()).isFalse();
        assertThat(pki.getChain()).containsExactly(pki.getRootCa());
        assertThat(pki.getIssuerCa()).isEqualTo(pki.getRootCa());

        X509Certificate leaf = pki.issueCert().subject("CN=solo").build();
        leaf.verify(pki.getRootCa().getPublicKey());
    }

    @Test
    void sanAutoDetectsDnsIpAndEmail() {
        TestPki pki = TestPki.create().build();

        IssuedCert issued = pki.issueCert()
                .subject("CN=host")
                .san("host.example.org", "10.0.0.1", "admin@example.org", "2001:db8::1")
                .issue();

        List<SubjectAlternativeName> sans = PkiCertInfo.of(issued.certificate()).getSans();
        assertThat(sans).contains(
                new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "host.example.org"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.IP_ADDRESS, "10.0.0.1"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.EMAIL, "admin@example.org"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.IP_ADDRESS, "2001:db8:0:0:0:0:0:1"));
    }

    @Test
    void expiredShortcutProducesExpiredCert() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject("CN=expired")
                .expired()
                .build();

        PkiCertInfo info = PkiCertInfo.of(cert);
        assertThat(info.isExpired()).isTrue();
    }

    @Test
    void notYetValidShortcutProducesFutureCert() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject("CN=future")
                .notYetValid()
                .build();

        assertThat(PkiCertInfo.of(cert).isNotYetValid()).isTrue();
    }

    @Test
    void subsequentIssuesProduceDistinctKeyPairs() {
        TestPki pki = TestPki.create().build();

        IssuedCert a = pki.issueCert().subject("CN=a").issue();
        IssuedCert b = pki.issueCert().subject("CN=b").issue();

        assertThat(a.publicKey()).isNotEqualTo(b.publicKey());
        assertThat(a.privateKey()).isNotEqualTo(b.privateKey());
    }

    @Test
    void extendedKeyUsageIsHonoured() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject("CN=client")
                .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
                .build();

        assertThat(PkiCertInfo.of(cert).getExtendedKeyUsages())
                .containsExactly(ExtendedKeyUsage.TLS_CLIENT);
    }

    @Test
    void keyUsageIsHonoured() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject("CN=srv")
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                .build();

        assertThat(PkiCertInfo.of(cert).getKeyUsages())
                .containsExactlyInAnyOrder(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT);
    }

    @Test
    void customValidityIsApplied() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject("CN=custom")
                .validFor(Duration.ofDays(7))
                .build();

        long days = java.time.temporal.ChronoUnit.DAYS.between(
                cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant());
        assertThat(days).isEqualTo(7);
    }

    @Test
    void ecLeafIsSupported() {
        TestPki pki = TestPki.create().build();

        IssuedCert issued = pki.issueCert()
                .subject("CN=ec-client")
                .ec(Curve.P_256)
                .issue();

        assertThat(issued.publicKey().getAlgorithm()).isEqualTo("EC");
        assertThat(PkiCertInfo.of(issued.certificate()).getPublicKeySize()).isEqualTo(256);
    }

    @Test
    void subjectIsRequired() {
        TestPki pki = TestPki.create().build();

        assertThatIllegalStateException()
                .isThrownBy(() -> pki.issueCert().build())
                .withMessageContaining("subject");
    }

    @Test
    void defaultChainValidatesAgainstTrustAnchors() {
        TestPki pki = TestPki.create()
                .withRootCa("CN=Default Root")
                .withIntermediateCa()
                .build();

        X509Certificate leaf = pki.issueCert().subject("CN=leaf").build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(pki.getChain())
                .trustAnchors(pki.getTrustAnchors())
                .validate();
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void trustAnchorsContainRootOnly() {
        TestPki pki = TestPki.create()
                .withRootCa("CN=Anchor Root")
                .withIntermediateCa()
                .build();

        Collection<X509Certificate> anchors = pki.getTrustAnchors();
        assertThat(anchors).containsExactly(pki.getRootCa());
    }

    @Test
    void subjectViaDnBuilderProducesExpectedDn() {
        TestPki pki = TestPki.create().build();

        X509Certificate cert = pki.issueCert()
                .subject(dn -> dn.cn("fluent").o("Acme").c("US"))
                .build();

        assertThat(cert.getSubjectX500Principal().getName())
                .contains("CN=fluent")
                .contains("O=Acme")
                .contains("C=US");
    }
}
