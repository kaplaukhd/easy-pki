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
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import io.github.kaplaukhd.easypki.CertificateProfile;
import io.github.kaplaukhd.easypki.CsrIssuancePolicy;
import io.github.kaplaukhd.easypki.CsrRequest;
import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.HashAlgorithm;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiCsr;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiSigner;
import io.github.kaplaukhd.easypki.RsaPssParameters;
import io.github.kaplaukhd.easypki.SubjectAlternativeName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CsrIssuanceValidationTest {
    @ParameterizedTest(name = "{0} CSR hierarchy, {1}")
    @CsvSource({"RSA, TLS_SERVER", "RSA, TLS_CLIENT", "EC, TLS_SERVER", "EC, TLS_CLIENT",
            "Ed25519, TLS_SERVER", "Ed25519, TLS_CLIENT", "PSS, TLS_SERVER", "PSS, TLS_CLIENT"})
    void parsedRequestsIssueAnIndependentlyValidatedHierarchy(String algorithm, CertificateProfile profile) throws Exception {
        Provider[] providers = Security.getProviders();
        Instant now = Instant.now();
        KeyPair rootKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate root = PkiCertificate.rootCa().subject("CN=CSR Root").keyPair(rootKeys).pathLength(1)
                .validFrom(now.minusSeconds(120)).validFor(Duration.ofDays(3650)).build();
        PkiIdentity rootIdentity = PkiIdentity.of(root, rootKeys.getPrivate());
        KeyPair intermediateKeys = keys(algorithm);
        CsrRequest caRequest = request(algorithm, intermediateKeys, "CN=CSR Intermediate", true);
        var caPolicy = CsrIssuancePolicy.forProfile(CertificateProfile.INTERMEDIATE_CA)
                .allowSubject(new X500Principal("CN=CSR Intermediate")::equals).allowCaRequests(0).build();
        X509Certificate intermediate = PkiCsr.issue(PkiCsr.fromPem(caRequest.toPem()), caPolicy)
                .issuer(rootIdentity).validFrom(now.minusSeconds(60)).validFor(Duration.ofDays(365)).build();
        PkiSigner intermediateSigner = signer(algorithm, intermediateKeys);
        PkiIdentity intermediateIdentity = PkiIdentity.of(intermediate, intermediateSigner, root);

        KeyPair leafKeys = keys(algorithm);
        CsrRequest leafRequest = request(algorithm, leafKeys, "", false);
        var leafPolicy = CsrIssuancePolicy.forProfile(profile)
                .allowSubject(new X500Principal("")::equals)
                .allowSan(name -> name.equals(new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "service.example")))
                .build();
        X509Certificate leaf = PkiCsr.issue(PkiCsr.fromDer(leafRequest.toDer()), leafPolicy)
                .issuer(intermediateIdentity).validFrom(now.minusSeconds(30)).validFor(Duration.ofDays(30)).build();

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        assertThat(factory.getProvider().getName()).isNotEqualTo("BC");
        X509Certificate decodedLeaf = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(leaf.getEncoded()));
        assertThat(decodedLeaf.getSubjectX500Principal()).isEqualTo(new X500Principal(""));
        assertThat(decodedLeaf.getPublicKey().getEncoded()).isEqualTo(leafKeys.getPublic().getEncoded());
        assertThat(decodedLeaf.getCriticalExtensionOIDs()).contains("2.5.29.17", "2.5.29.19", "2.5.29.15");
        assertThat(decodedLeaf.getSubjectAlternativeNames()).containsExactly(List.of(2, "service.example"));
        assertThat(decodedLeaf.getExtendedKeyUsage()).containsExactly(profile == CertificateProfile.TLS_SERVER
                ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2");
        assertThat(intermediate.getBasicConstraints()).isZero();
        assertThat(decodedLeaf.getBasicConstraints()).isEqualTo(-1);
        var path = factory.generateCertPath(List.of(decodedLeaf, intermediate));
        var parameters = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
        parameters.setDate(Date.from(now));
        parameters.setRevocationEnabled(false);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        assertThat(validator.getProvider().getName()).isNotEqualTo("BC");
        validator.validate(path, parameters);
        assertThat(CertValidator.of(decodedLeaf).chain(intermediate).trustAnchors(root).at(now).validate().isValid()).isTrue();
        assertThat(CertValidator.of(decodedLeaf).chain(intermediate, root).at(now).validate().isTrusted()).isFalse();
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    private static CsrRequest request(String algorithm, KeyPair keys, String subject, boolean ca) {
        var builder = PkiCsr.create().subject(subject).signer(keys.getPublic(), signer(algorithm, keys));
        if (ca) builder.pathLength(0); else builder.san(s -> s.dns("service.example"));
        return builder.build();
    }

    private static PkiSigner signer(String algorithm, KeyPair keys) {
        return "PSS".equals(algorithm)
                ? PkiSigner.rsaPss(keys.getPrivate(), new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA384, 24))
                : PkiSigner.jca(keys.getPrivate());
    }

    private static KeyPair keys(String algorithm) {
        return switch (algorithm) {
            case "RSA", "PSS" -> PkiKeys.rsa(2048);
            case "EC" -> PkiKeys.ec(Curve.P_256);
            case "Ed25519" -> PkiKeys.ed25519();
            default -> throw new IllegalArgumentException(algorithm);
        };
    }
}
