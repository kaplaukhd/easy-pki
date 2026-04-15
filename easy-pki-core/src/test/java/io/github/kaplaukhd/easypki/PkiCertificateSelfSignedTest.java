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
package io.github.kaplaukhd.easypki;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;

class PkiCertificateSelfSignedTest {

    @Test
    void buildsValidRsaCertificate() throws Exception {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=example.com, O=Corp, C=RU")
                .keyPair(keys)
                .validFor(Duration.ofDays(365))
                .build();

        assertThat(cert.getSubjectX500Principal().getName())
                .contains("CN=example.com")
                .contains("O=Corp")
                .contains("C=RU");
        // self-signed invariant: issuer == subject
        assertThat(cert.getIssuerX500Principal()).isEqualTo(cert.getSubjectX500Principal());
        // signature verifies against own public key
        cert.verify(keys.getPublic());
        // default signature algorithm for RSA keys
        assertThat(cert.getSigAlgName()).isEqualToIgnoringCase("SHA256withRSA");
    }

    @Test
    void dnBuilderOverloadProducesSameResultAsStringOverload() throws Exception {
        KeyPair keys = PkiKeys.rsa(2048);
        Duration validity = Duration.ofDays(30);

        X509Certificate a = PkiCertificate.selfSigned()
                .subject("CN=host.example, O=Acme, C=US")
                .keyPair(keys).validFor(validity).build();

        X509Certificate b = PkiCertificate.selfSigned()
                .subject(dn -> dn.cn("host.example").o("Acme").c("US"))
                .keyPair(keys).validFor(validity).build();

        assertThat(a.getSubjectX500Principal()).isEqualTo(b.getSubjectX500Principal());
    }

    @Test
    void ecKeyProducesEcdsaSignature() throws Exception {
        KeyPair keys = PkiKeys.ec(Curve.P_256);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=ec-host")
                .keyPair(keys)
                .validFor(Duration.ofDays(30))
                .build();

        cert.verify(keys.getPublic());
        assertThat(cert.getSigAlgName()).isEqualToIgnoringCase("SHA256withECDSA");
    }

    @Test
    void serialNumberIsRandomAndPositiveByDefault() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate a = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys).validFor(Duration.ofDays(1)).build();
        X509Certificate b = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys).validFor(Duration.ofDays(1)).build();

        assertThat(a.getSerialNumber()).isNotEqualTo(b.getSerialNumber());
        assertThat(a.getSerialNumber().signum()).isOne();
        assertThat(b.getSerialNumber().signum()).isOne();
    }

    @Test
    void explicitSerialNumberIsHonoured() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys).validFor(Duration.ofDays(1))
                .serialNumber(BigInteger.valueOf(42))
                .build();

        assertThat(cert.getSerialNumber()).isEqualTo(BigInteger.valueOf(42));
    }

    @Test
    void negativeOrZeroSerialIsRejected() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCertificate.selfSigned().serialNumber(BigInteger.ZERO));
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCertificate.selfSigned().serialNumber(BigInteger.valueOf(-1)));
    }

    @Test
    void validFromAndValidUntilOverrideDefaults() {
        KeyPair keys = PkiKeys.rsa(2048);
        Instant notBefore = Instant.parse("2030-01-01T00:00:00Z");
        Instant notAfter = Instant.parse("2031-01-01T00:00:00Z");

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys)
                .validFrom(notBefore).validUntil(notAfter)
                .build();

        assertThat(cert.getNotBefore().toInstant()).isEqualTo(notBefore);
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(notAfter);
    }

    @Test
    void validForSetsNotAfterRelativeToNotBefore() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys)
                .validFor(Duration.ofDays(10))
                .build();

        long daysBetween = ChronoUnit.DAYS.between(
                cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant());
        assertThat(daysBetween).isEqualTo(10);
    }

    @Test
    void nonPositiveValidForIsRejected() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCertificate.selfSigned().validFor(Duration.ZERO));
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCertificate.selfSigned().validFor(Duration.ofDays(-1)));
    }

    @Test
    void isCaAddsBasicConstraintsTrueAndAllowsInfinitePathLength() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(keys)
                .validFor(Duration.ofDays(365)).isCA(true)
                .build();

        assertThat(cert.getBasicConstraints()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void pathLengthAppliesAndImpliesIsCa() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(keys)
                .validFor(Duration.ofDays(365))
                .pathLength(2)
                .build();

        assertThat(cert.getBasicConstraints()).isEqualTo(2);
    }

    @Test
    void nonCaHasBasicConstraintsFalse() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=leaf").keyPair(keys)
                .validFor(Duration.ofDays(30))
                .build();

        // -1 means "not a CA"
        assertThat(cert.getBasicConstraints()).isEqualTo(-1);
    }

    @Test
    void negativePathLengthIsRejected() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCertificate.selfSigned().pathLength(-1));
    }

    @Test
    void keyUsageExtensionReflectsRequestedBits() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(keys)
                .validFor(Duration.ofDays(365))
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        // JDK order: digitalSignature, nonRepudiation, keyEncipherment,
        // dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
        boolean[] usage = cert.getKeyUsage();
        assertThat(usage).isNotNull();
        assertThat(usage[5]).isTrue(); // keyCertSign
        assertThat(usage[6]).isTrue(); // cRLSign
        assertThat(usage[0]).isFalse(); // digitalSignature not requested
    }

    @Test
    void skiAndAkiExtensionsArePresentAndMatchForSelfSigned() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(keys)
                .validFor(Duration.ofDays(365))
                .build();

        byte[] skiExt = cert.getExtensionValue("2.5.29.14"); // subjectKeyIdentifier
        byte[] akiExt = cert.getExtensionValue("2.5.29.35"); // authorityKeyIdentifier

        assertThat(skiExt).as("SKI extension").isNotNull();
        assertThat(akiExt).as("AKI extension").isNotNull();
    }

    @Test
    void signatureAlgorithmOverrideIsHonoured() throws Exception {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=a").keyPair(keys)
                .validFor(Duration.ofDays(1))
                .signatureAlgorithm("SHA384withRSA")
                .build();

        assertThat(cert.getSigAlgName()).isEqualToIgnoringCase("SHA384withRSA");
        cert.verify(keys.getPublic());
    }

    @Test
    void missingSubjectRejected() {
        KeyPair keys = PkiKeys.rsa(2048);
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCertificate.selfSigned()
                        .keyPair(keys).validFor(Duration.ofDays(1)).build())
                .withMessageContaining("subject");
    }

    @Test
    void missingKeyPairRejected() {
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCertificate.selfSigned()
                        .subject("CN=a").validFor(Duration.ofDays(1)).build())
                .withMessageContaining("keyPair");
    }

    @Test
    void missingValidityRejected() {
        KeyPair keys = PkiKeys.rsa(2048);
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCertificate.selfSigned()
                        .subject("CN=a").keyPair(keys).build())
                .withMessageContaining("validFor");
    }

    @Test
    void nullArgumentsRejected() {
        assertThatNullPointerException().isThrownBy(() ->
                PkiCertificate.selfSigned().subject((String) null));
        assertThatNullPointerException().isThrownBy(() ->
                PkiCertificate.selfSigned().subject((java.util.function.Consumer<DnBuilder>) null));
        assertThatNullPointerException().isThrownBy(() ->
                PkiCertificate.selfSigned().keyPair(null));
    }
}
