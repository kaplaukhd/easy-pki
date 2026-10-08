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
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiCertificates;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import org.bouncycastle.cert.X509CRLHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Ed25519ValidationTest {

    @ParameterizedTest(name = "PKCS12-reloaded signing key: {0}")
    @ValueSource(booleans = {false, true})
    void defaultEd25519CrlsReportGoodAndRevokedCertificates(boolean reload) throws Exception {
        Provider[] providers = Security.getProviders();
        Instant start = Instant.now().minusSeconds(60);
        var keys = PkiKeys.ed25519();
        var root = PkiCertificate.selfSigned().subject("CN=Ed25519 CRL Root")
                .keyPair(keys).validFrom(start).validFor(Duration.ofDays(30))
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        var signingKey = keys.getPrivate();
        if (reload) {
            signingKey = PkiPkcs12.load(PkiPkcs12.create().certificate(root)
                    .privateKey(signingKey).password("password").build().toBytes(), "password")
                    .getPrivateKey();
        }
        assertThat(signingKey.getAlgorithm()).isEqualTo(reload ? "EdDSA" : "Ed25519");
        var leaf = PkiCertificate.signed().subject("CN=CRL Target")
                .keyPair(PkiKeys.ed25519()).issuer(root, signingKey)
                .validFrom(start).validFor(Duration.ofDays(1)).build();
        X509CRL goodCrl = PkiCrl.issued().issuer(root, signingKey)
                .thisUpdate(start).nextUpdate(Duration.ofHours(1)).build();
        assertEd25519CrlSignature(goodCrl, root);
        ValidationResult good = CertValidator.of(leaf).trustAnchors(root).crl(goodCrl).validate();
        assertThat(good.getErrors()).isEmpty();
        assertThat(good.isValid()).isTrue();
        assertThat(good.isRevoked()).isFalse();

        X509CRL revokedCrl = PkiCrl.issued().issuer(root, signingKey)
                .thisUpdate(start).nextUpdate(Duration.ofHours(1))
                .revoke(leaf.getSerialNumber(), RevocationReason.KEY_COMPROMISE, start).build();
        assertEd25519CrlSignature(revokedCrl, root);
        ValidationResult revoked = CertValidator.of(leaf).trustAnchors(root).crl(revokedCrl).validate();
        assertThat(revoked.isValid()).isFalse();
        assertThat(revoked.isRevoked()).isTrue();
        assertThat(revoked.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(revoked.getErrors()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.REVOKED);
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void ed448CrlDefaultsAreNotInferredAsEd25519() throws Exception {
        var keys = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
        assertThat(keys.getPrivate().getAlgorithm()).isEqualTo("EdDSA");
        var root = PkiCertificate.selfSigned().subject("CN=Explicit Ed448 CRL Root")
                .keyPair(keys).signatureAlgorithm("Ed448").validFor(Duration.ofDays(1))
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        assertThatIllegalStateException().isThrownBy(() -> PkiCrl.issued()
                .issuer(root, keys.getPrivate()).nextUpdate(Duration.ofHours(1)).build())
                .withMessageContaining("No default signature algorithm");
        X509CRL explicit = PkiCrl.issued().issuer(root, keys.getPrivate())
                .signatureAlgorithm("Ed448").nextUpdate(Duration.ofHours(1)).build();
        assertThat(explicit.getSigAlgOID()).isEqualTo("1.3.101.113");
        explicit.verify(root.getPublicKey());
    }

    @Test
    void reloadedEd25519HierarchyPassesIndependentJcaPkixAndLibraryValidation() throws Exception {
        Provider[] providers = Security.getProviders();
        Instant start = Instant.now().minusSeconds(60);
        var rootKeys = PkiKeys.ed25519();
        var root = PkiCertificate.selfSigned().subject("CN=Ed25519 Root")
                .keyPair(rootKeys).validFrom(start).validFor(Duration.ofDays(30))
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        // JDK PKCS12 reloads the signing key as an EdECKey named "EdDSA".
        var rootIdentity = PkiPkcs12.load(PkiPkcs12.create().certificate(root)
                .privateKey(rootKeys.getPrivate()).password("password").build().toBytes(), "password");
        assertThat(rootIdentity.getPrivateKey().getAlgorithm()).isEqualTo("EdDSA");
        var intermediateKeys = PkiKeys.ed25519();
        var intermediate = PkiCertificate.signed().subject("CN=Ed25519 Intermediate")
                .keyPair(intermediateKeys).issuer(rootIdentity.getCertificate(), rootIdentity.getPrivateKey())
                .validFrom(start).validFor(Duration.ofDays(14)).pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        var leaf = PkiCertificate.signed().subject("CN=service.example")
                .keyPair(PkiKeys.ed25519()).issuer(intermediate, intermediateKeys.getPrivate())
                .validFrom(start).validFor(Duration.ofDays(1))
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE).extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
                .san(s -> s.dns("service.example").ip("192.0.2.10").ip("2001:db8::1")).build();
        var reloadedRoot = PkiCertificates.fromPem(PkiCertificates.toPem(root));
        var reloadedIntermediate = PkiCertificates.fromDer(PkiCertificates.toDer(intermediate));
        var reloadedLeaf = PkiCertificates.fromPem(PkiCertificates.toPem(leaf));
        var path = CertificateFactory.getInstance("X.509")
                .generateCertPath(List.of(reloadedLeaf, reloadedIntermediate));
        var parameters = new PKIXParameters(Set.of(new TrustAnchor(reloadedRoot, null)));
        parameters.setRevocationEnabled(false);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        assertThat(validator.getProvider().getName()).isNotEqualTo("BC");
        var validated = (PKIXCertPathValidatorResult) validator.validate(path, parameters);
        assertThat(validated.getTrustAnchor().getTrustedCert()).isEqualTo(root);
        assertThat(validated.getPublicKey()).isEqualTo(leaf.getPublicKey());

        ValidationResult result = CertValidator.of(reloadedLeaf).chain(reloadedIntermediate)
                .trustAnchors(reloadedRoot).validate();
        assertThat(result.getErrors()).isEmpty();
        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
        assertThat(ChainBuilder.of(reloadedLeaf).intermediates(reloadedIntermediate)
                .trustAnchors(reloadedRoot).build().validate().isValid()).isTrue();
        assertThat(CertValidator.of(reloadedLeaf).chain(reloadedIntermediate, reloadedRoot)
                .validate().isTrusted()).isFalse();
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    private static void assertEd25519CrlSignature(X509CRL crl, X509Certificate issuer) throws Exception {
        assertThat(crl.getSigAlgOID()).isEqualTo("1.3.101.112");
        var holder = new X509CRLHolder(crl.getEncoded());
        assertThat(holder.toASN1Structure().getSignatureAlgorithm().getParameters()).isNull();
        assertThat(holder.toASN1Structure().getTBSCertList().getSignature())
                .isEqualTo(holder.toASN1Structure().getSignatureAlgorithm());
        Signature verifier = Signature.getInstance("Ed25519");
        assertThat(verifier.getProvider().getName()).isNotEqualTo("BC");
        verifier.initVerify(issuer.getPublicKey());
        verifier.update(crl.getTBSCertList());
        assertThat(verifier.verify(crl.getSignature())).isTrue();
        crl.verify(issuer.getPublicKey());
    }
}
