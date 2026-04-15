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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class PkiCertInfoTest {

    @Test
    void basicFieldsOnSelfSignedCertificate() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=example.com, O=Acme, C=RU")
                .keyPair(keys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .pathLength(1)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        PkiCertInfo info = PkiCertInfo.of(cert);

        assertThat(info.getSubject()).contains("CN=example.com");
        assertThat(info.getIssuer()).isEqualTo(info.getSubject());
        assertThat(info.isSelfSigned()).isTrue();
        assertThat(info.getSerialNumber().signum()).isOne();
        assertThat(info.isCA()).isTrue();
        assertThat(info.getPathLength()).isEqualTo(1);
        assertThat(info.getKeyUsages())
                .containsExactlyInAnyOrder(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
        assertThat(info.getPublicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(info.getPublicKeySize()).isEqualTo(2048);
    }

    @Test
    void expiryChecks() {
        KeyPair keys = PkiKeys.rsa(2048);

        X509Certificate expired = PkiCertificate.selfSigned()
                .subject("CN=expired").keyPair(keys)
                .validFrom(Instant.now().minus(Duration.ofDays(60)))
                .validUntil(Instant.now().minus(Duration.ofDays(1)))
                .build();
        assertThat(PkiCertInfo.of(expired).isExpired()).isTrue();
        assertThat(PkiCertInfo.of(expired).isExpiringWithin(Duration.ofDays(1))).isTrue();

        X509Certificate future = PkiCertificate.selfSigned()
                .subject("CN=future").keyPair(keys)
                .validFrom(Instant.now().plus(Duration.ofDays(10)))
                .validUntil(Instant.now().plus(Duration.ofDays(40)))
                .build();
        assertThat(PkiCertInfo.of(future).isNotYetValid()).isTrue();
        assertThat(PkiCertInfo.of(future).isExpired()).isFalse();

        X509Certificate soon = PkiCertificate.selfSigned()
                .subject("CN=soon").keyPair(keys)
                .validFor(Duration.ofDays(10))
                .build();
        assertThat(PkiCertInfo.of(soon).isExpired()).isFalse();
        assertThat(PkiCertInfo.of(soon).isExpiringWithin(Duration.ofDays(30))).isTrue();
        assertThat(PkiCertInfo.of(soon).isExpiringWithin(Duration.ofDays(5))).isFalse();
    }

    @Test
    void basicConstraintsInfiniteCaReportsNullPathLength() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(keys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();

        PkiCertInfo info = PkiCertInfo.of(cert);
        assertThat(info.isCA()).isTrue();
        assertThat(info.getPathLength()).isNull();
    }

    @Test
    void nonCaReportsFalseAndNullPathLength() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=leaf").keyPair(keys)
                .validFor(Duration.ofDays(30))
                .build();

        PkiCertInfo info = PkiCertInfo.of(cert);
        assertThat(info.isCA()).isFalse();
        assertThat(info.getPathLength()).isNull();
    }

    @Test
    void extendedKeyUsageIsReadBackAsEnum() {
        KeyPair rootKeys = PkiKeys.rsa(2048);
        X509Certificate root = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(rootKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf").publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT)
                .build();

        PkiCertInfo info = PkiCertInfo.of(leaf);
        assertThat(info.getExtendedKeyUsages())
                .containsExactlyInAnyOrder(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT);
        assertThat(info.hasExtendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)).isTrue();
        assertThat(info.hasExtendedKeyUsage("1.3.6.1.5.5.7.3.1")).isTrue();
        assertThat(info.hasExtendedKeyUsage(ExtendedKeyUsage.CODE_SIGNING)).isFalse();
    }

    @Test
    void sansAreExtractedWithType() {
        KeyPair rootKeys = PkiKeys.rsa(2048);
        X509Certificate root = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(rootKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=api").publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .san(s -> s.dns("api.example.com").ip("10.0.0.1").email("a@b.com"))
                .build();

        PkiCertInfo info = PkiCertInfo.of(leaf);
        assertThat(info.getSans())
                .containsExactlyInAnyOrder(
                        new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "api.example.com"),
                        new SubjectAlternativeName(SubjectAlternativeName.Type.IP_ADDRESS, "10.0.0.1"),
                        new SubjectAlternativeName(SubjectAlternativeName.Type.EMAIL, "a@b.com"));
    }

    @Test
    void emptySansWhenExtensionAbsent() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=nosan").keyPair(keys)
                .validFor(Duration.ofDays(1)).build();

        assertThat(PkiCertInfo.of(cert).getSans()).isEmpty();
    }

    @Test
    void ocspAndCrlUrlsExtractedFromExtensions() {
        KeyPair rootKeys = PkiKeys.rsa(2048);
        X509Certificate root = PkiCertificate.selfSigned()
                .subject("CN=root").keyPair(rootKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf").publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .ocsp("http://ocsp.example.org")
                .ocsp("http://ocsp2.example.org")
                .crlDistributionPoint("http://crl.example.org/a.crl")
                .build();

        PkiCertInfo info = PkiCertInfo.of(leaf);
        assertThat(info.getOcspUrls())
                .containsExactly("http://ocsp.example.org", "http://ocsp2.example.org");
        assertThat(info.getCrlUrls())
                .containsExactly("http://crl.example.org/a.crl");
    }

    @Test
    void publicKeySizeForEcCurves() {
        X509Certificate p256 = PkiCertificate.selfSigned()
                .subject("CN=ec").keyPair(PkiKeys.ec(Curve.P_256))
                .validFor(Duration.ofDays(1)).build();
        X509Certificate p384 = PkiCertificate.selfSigned()
                .subject("CN=ec").keyPair(PkiKeys.ec(Curve.P_384))
                .validFor(Duration.ofDays(1)).build();

        assertThat(PkiCertInfo.of(p256).getPublicKeyAlgorithm()).isEqualTo("EC");
        assertThat(PkiCertInfo.of(p256).getPublicKeySize()).isEqualTo(256);
        assertThat(PkiCertInfo.of(p384).getPublicKeySize()).isEqualTo(384);
    }

    @Test
    void fingerprintIsColonSeparatedUppercaseHex() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=fp").keyPair(keys).validFor(Duration.ofDays(1)).build();

        PkiCertInfo info = PkiCertInfo.of(cert);
        String sha256 = info.getFingerprint(HashAlgorithm.SHA256);

        // 32 bytes → 32 groups of two hex chars joined by 31 colons.
        assertThat(sha256).matches("^[0-9A-F]{2}(:[0-9A-F]{2}){31}$");
        // SHA-1 = 20 bytes
        assertThat(info.getFingerprint(HashAlgorithm.SHA1))
                .matches("^[0-9A-F]{2}(:[0-9A-F]{2}){19}$");
    }

    @Test
    void fingerprintIsStableAcrossCalls() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=fp").keyPair(keys).validFor(Duration.ofDays(1)).build();

        PkiCertInfo info = PkiCertInfo.of(cert);
        assertThat(info.getFingerprint(HashAlgorithm.SHA256))
                .isEqualTo(info.getFingerprint(HashAlgorithm.SHA256));
    }
}
