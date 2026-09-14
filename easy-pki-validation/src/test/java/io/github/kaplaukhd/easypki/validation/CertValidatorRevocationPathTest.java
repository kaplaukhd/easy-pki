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
import java.util.List;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CertValidatorRevocationPathTest {
    private static KeyPair rootKeys;
    private static KeyPair intermediateKeys;
    private static X509Certificate root;
    private static X509Certificate intermediate;
    private static X509Certificate leaf;
    private static X509Certificate directLeaf;

    @BeforeAll
    static void hierarchy() {
        rootKeys = PkiKeys.ec(Curve.P_256);
        intermediateKeys = PkiKeys.ec(Curve.P_256);
        root = PkiCertificate.selfSigned().subject("CN=Revocation root").keyPair(rootKeys)
                .validFor(Duration.ofDays(365)).isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        intermediate = PkiCertificate.signed().subject("CN=Revocation intermediate")
                .publicKey(intermediateKeys.getPublic()).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(180)).pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        leaf = issued(intermediate, intermediateKeys, "leaf");
        directLeaf = issued(root, rootKeys, "direct leaf");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void revokedLeafIsCheckedWithIncludedOrOmittedAnchor(boolean includeAnchor) {
        X509CRL crl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(directLeaf, RevocationReason.KEY_COMPROMISE).build();
        CertValidator validator = CertValidator.of(directLeaf).trustAnchors(root).crl(crl);
        if (includeAnchor) validator.chain(root);

        ValidationResult result = validator.validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(result.getValidationPath()).isEqualTo(
                includeAnchor ? List.of(directLeaf, root) : List.of(directLeaf));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void finalIntermediateIsCheckedWithIncludedOrOmittedAnchor(boolean includeAnchor) {
        X509CRL leafCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(intermediate, intermediateKeys.getPrivate()).build();
        X509CRL caCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(intermediate, RevocationReason.CA_COMPROMISE).build();
        CertValidator validator = CertValidator.of(leaf).chain(intermediate)
                .trustAnchors(root).crl(leafCrl, caCrl);
        if (includeAnchor) validator.chain(root);

        ValidationResult result = validator.validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.CA_COMPROMISE);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void trustedIntermediateIsAnExemptAnchor(boolean includeAnchor) {
        X509CRL leafCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(intermediate, intermediateKeys.getPrivate()).build();
        X509CRL caCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(intermediate, RevocationReason.CA_COMPROMISE).build();
        CertValidator validator = CertValidator.of(leaf).trustAnchors(intermediate).crl(leafCrl, caCrl);
        if (includeAnchor) validator.chain(intermediate);
        assertThat(validator.validate().isValid()).isTrue();
    }

    @Test
    void directlyTrustedTargetRemainsExemptFromRevocation() {
        X509CRL crl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(directLeaf, RevocationReason.KEY_COMPROMISE).build();
        assertThat(CertValidator.of(directLeaf).trustAnchors(directLeaf).crl(crl)
                .validate().isValid()).isTrue();
    }

    @Test
    void omittedAnchorUsesTheActualSignerAmongSameNameCandidates() {
        X509Certificate decoy = PkiCertificate.selfSigned().subject("CN=Revocation root")
                .keyPair(PkiKeys.ec(Curve.P_256)).isCA(true).validFor(Duration.ofDays(365)).build();
        X509CRL crl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(directLeaf, RevocationReason.KEY_COMPROMISE).build();
        ValidationResult result = CertValidator.of(directLeaf).trustAnchors(decoy, root)
                .crl(crl).validate();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.isTrusted()).isTrue();
    }

    @Test
    void omittedAnchorDoesNotTurnMissingLeafRevocationDataIntoSuccess() {
        ValidationResult result = CertValidator.of(directLeaf).trustAnchors(root)
                .crl(List.of()).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).extracting(ValidationError::code)
                .contains(ValidationError.Code.REVOCATION_UNKNOWN);
    }

    @Test
    void completeGoodChainWithOmittedAnchorPasses() {
        X509CRL leafCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(intermediate, intermediateKeys.getPrivate()).build();
        X509CRL caCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate()).build();
        assertThat(CertValidator.of(leaf).chain(intermediate).trustAnchors(root)
                .crl(leafCrl, caCrl).validate().isValid()).isTrue();
    }

    @Test
    void intermediateWithoutSourcesKeepsItsExistingPolicyWithAnExplicitWarning() {
        X509CRL leafCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24))
                .issuer(intermediate, intermediateKeys.getPrivate()).build();
        ValidationResult result = CertValidator.of(leaf).chain(intermediate).trustAnchors(root)
                .crl(leafCrl).validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.REVOCATION_UNKNOWN);
        assertThat(result.getWarnings().get(0).message()).contains("Revocation intermediate");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ldap://directory.example.test/cn=Root", "not a uri"})
    void unsupportedIntermediateSourcesRetainTheNoSourcePolicy(String distributionPoint) {
        X509Certificate ca = PkiCertificate.signed().subject("CN=Unsupported CDP intermediate")
                .publicKey(intermediateKeys.getPublic()).issuer(root, rootKeys.getPrivate())
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .validFor(Duration.ofDays(90)).crlDistributionPoint(distributionPoint).build();
        X509Certificate child = issued(ca, intermediateKeys, "unsupported CDP leaf");
        X509CRL childCrl = PkiCrl.issued().nextUpdate(Duration.ofHours(24))
                .issuer(ca, intermediateKeys.getPrivate()).build();

        ValidationResult result = CertValidator.of(child).chain(ca).trustAnchors(root)
                .crl(c -> c.add(childCrl).autoFetch()).validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .contains(ValidationError.Code.REVOCATION_UNKNOWN);
        assertThat(result.getWarnings()).anySatisfy(w -> assertThat(w.message()).contains(distributionPoint));
    }

    private static X509Certificate issued(X509Certificate issuer, KeyPair keys, String cn) {
        return PkiCertificate.signed().subject("CN=" + cn)
                .publicKey(PkiKeys.ec(Curve.P_256).getPublic()).issuer(issuer, keys.getPrivate())
                .validFor(Duration.ofDays(30)).build();
    }
}
