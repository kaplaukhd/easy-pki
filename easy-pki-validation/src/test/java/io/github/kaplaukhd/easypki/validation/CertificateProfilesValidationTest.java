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

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import io.github.kaplaukhd.easypki.CertificateProfile;
import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CertificateProfilesValidationTest {

    @ParameterizedTest(name = "{0} {1} profile hierarchy passes independent JCA PKIX")
    @CsvSource({
        "RSA, TLS_SERVER",
        "RSA, TLS_CLIENT",
        "EC, TLS_SERVER",
        "EC, TLS_CLIENT",
        "Ed25519, TLS_SERVER",
        "Ed25519, TLS_CLIENT"
    })
    void profileHierarchyPassesIndependentJcaAndExplicitTrustValidation(
            String algorithm, CertificateProfile profile) throws Exception {
        Provider[] providers = Security.getProviders();
        Instant now = Instant.now();
        KeyPair rootKeys = keys(algorithm);
        X509Certificate root = PkiCertificate.rootCa()
                .subject("CN=" + algorithm + " Profile Root")
                .keyPair(rootKeys)
                .validFrom(now.minusSeconds(120)).validFor(Duration.ofDays(3650))
                .build();
        PkiIdentity rootIdentity = PkiIdentity.of(root, rootKeys.getPrivate());

        KeyPair intermediateKeys = keys(algorithm);
        X509Certificate intermediate = PkiCertificate.intermediateCa()
                .subject("CN=" + algorithm + " Profile Intermediate")
                .keyPair(intermediateKeys).issuer(rootIdentity)
                .validFrom(now.minusSeconds(60)).validFor(Duration.ofDays(365))
                .build();
        PkiIdentity intermediateIdentity = PkiIdentity.of(
                intermediate, intermediateKeys.getPrivate(), root);

        var leafBuilder = profile == CertificateProfile.TLS_SERVER
                ? PkiCertificate.tlsServer().subject("CN=service.example")
                        .san(s -> s.dns("service.example").ip("192.0.2.10").ip("2001:db8::1"))
                : PkiCertificate.tlsClient().subject("CN=Profile Client");
        X509Certificate leaf = leafBuilder.keyPair(keys(algorithm)).issuer(intermediateIdentity)
                .validFrom(now.minusSeconds(30)).validFor(Duration.ofDays(30))
                .build();

        // Decode the emitted DER with the host JCA provider, independently of library helpers.
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        assertThat(factory.getProvider().getName()).isNotEqualTo("BC");
        X509Certificate decodedRoot = decode(factory, root);
        X509Certificate decodedIntermediate = decode(factory, intermediate);
        X509Certificate decodedLeaf = decode(factory, leaf);
        decodedRoot.verify(decodedRoot.getPublicKey());
        decodedIntermediate.verify(decodedRoot.getPublicKey());
        decodedLeaf.verify(decodedIntermediate.getPublicKey());
        assertThat(decodedRoot.getBasicConstraints()).isEqualTo(Integer.MAX_VALUE);
        assertThat(decodedIntermediate.getBasicConstraints()).isZero();
        assertThat(decodedLeaf.getBasicConstraints()).isEqualTo(-1);
        for (X509Certificate ca : List.of(decodedRoot, decodedIntermediate)) {
            assertThat(ca.getCriticalExtensionOIDs()).contains("2.5.29.19", "2.5.29.15");
            assertThat(ca.getKeyUsage())
                    .containsExactly(false, false, false, false, false, true, true, false, false);
        }
        assertThat(decodedLeaf.getCriticalExtensionOIDs()).contains("2.5.29.19", "2.5.29.15");
        assertThat(decodedLeaf.getNonCriticalExtensionOIDs()).contains("2.5.29.37");
        assertThat(decodedLeaf.getKeyUsage())
                .containsExactly(true, false, false, false, false, false, false, false, false);
        assertThat(decodedLeaf.getExtendedKeyUsage()).containsExactly(
                profile == CertificateProfile.TLS_SERVER ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2");

        var path = factory.generateCertPath(List.of(decodedLeaf, decodedIntermediate));
        var parameters = new PKIXParameters(Set.of(new TrustAnchor(decodedRoot, null)));
        parameters.setRevocationEnabled(false);
        parameters.setDate(Date.from(now));
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        assertThat(validator.getProvider().getName()).isNotEqualTo("BC");
        var validated = (PKIXCertPathValidatorResult) validator.validate(path, parameters);
        assertThat(validated.getTrustAnchor().getTrustedCert()).isEqualTo(decodedRoot);
        assertThat(validated.getPublicKey().getEncoded()).isEqualTo(decodedLeaf.getPublicKey().getEncoded());

        ValidationResult result = CertValidator.of(decodedLeaf).chain(decodedIntermediate)
                .trustAnchors(decodedRoot).at(now).validate();
        assertThat(result.getErrors()).isEmpty();
        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
        assertThat(ChainBuilder.of(decodedLeaf).intermediates(decodedIntermediate)
                .trustAnchors(decodedRoot).build().validate().isValid()).isTrue();

        ValidationResult untrusted = CertValidator.of(decodedLeaf).chain(decodedIntermediate, decodedRoot)
                .at(now).validate();
        assertThat(untrusted.isValid()).isFalse();
        assertThat(untrusted.isTrusted()).isFalse();
        assertThat(untrusted.getErrors()).extracting(ValidationError::code)
                .contains(ValidationError.Code.UNTRUSTED_ROOT);
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    private static X509Certificate decode(CertificateFactory factory, X509Certificate certificate)
            throws Exception {
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    private static KeyPair keys(String algorithm) {
        return switch (algorithm) {
            case "RSA" -> PkiKeys.rsa(2048);
            case "EC" -> PkiKeys.ec(Curve.P_256);
            case "Ed25519" -> PkiKeys.ed25519();
            default -> throw new IllegalArgumentException("Unsupported test key algorithm: " + algorithm);
        };
    }
}
