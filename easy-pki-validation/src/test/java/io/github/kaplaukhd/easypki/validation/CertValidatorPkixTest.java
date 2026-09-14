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
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CertValidatorPkixTest {

    private static KeyPair rootKeys;
    private static X509Certificate root;
    private static KeyPair intermediateKeys;
    private static X509Certificate intermediate;
    private static KeyPair leafKeys;
    private static X509Certificate leaf;

    @BeforeAll
    static void hierarchy() {
        rootKeys = PkiKeys.ec(Curve.P_256);
        root = PkiCertificate.selfSigned().subject("CN=PKIX Root")
                .keyPair(rootKeys).validFor(Duration.ofDays(3650))
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        intermediateKeys = PkiKeys.ec(Curve.P_256);
        intermediate = PkiCertificate.signed().subject("CN=PKIX Intermediate")
                .keyPair(intermediateKeys).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365)).pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        leafKeys = PkiKeys.ec(Curve.P_256);
        leaf = leafIssuedBy(intermediate, intermediateKeys.getPrivate(), "service.example.com");
    }

    @Test
    void suppliedChainCannotEstablishTrust() {
        ValidationResult result = CertValidator.of(leaf).chain(intermediate, root).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.isTrusted()).isFalse();
        assertThat(result.getErrors()).extracting(ValidationError::code)
                .contains(ValidationError.Code.UNTRUSTED_ROOT);
    }

    @Test
    void selfSignedCertificateCannotEstablishItsOwnTrust() {
        assertThat(CertValidator.of(root).validate().isValid()).isFalse();
        assertThat(CertValidator.of(root).trustAnchors(root).validate().isValid()).isTrue();
    }

    @Test
    void explicitRootWorksWithOrWithoutTheAnchorInTheSuppliedChain() {
        ValidationResult included = CertValidator.of(leaf).chain(intermediate, root)
                .trustAnchors(root).validate();
        ValidationResult omitted = CertValidator.of(leaf).chain(intermediate)
                .trustAnchors(List.of(root)).validate();
        assertThat(included.isValid()).isTrue();
        assertThat(omitted.isValid()).isTrue();
        assertThat(omitted.isTrusted()).isTrue();
        assertThat(included.getValidationPath()).containsExactly(leaf, intermediate, root);
        assertThat(omitted.getValidationPath()).containsExactly(leaf, intermediate);
    }

    @Test
    void explicitIntermediateWorksWithOrWithoutTheAnchorInTheSuppliedChain() {
        assertThat(CertValidator.of(leaf).chain(intermediate)
                .trustAnchors(List.of(intermediate)).validate().isValid()).isTrue();
        assertThat(CertValidator.of(leaf).trustAnchors(intermediate).validate().isValid()).isTrue();
        assertThat(CertValidator.of(intermediate)
                .trustAnchors(intermediate).validate().isValid()).isTrue();
    }

    @Test
    void suppliedChainIsNotTruncatedAtAnIntermediateAnchor() {
        ValidationResult result = CertValidator.of(leaf).chain(intermediate, root)
                .trustAnchors(intermediate).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getValidationPath()).containsExactly(leaf, intermediate, root);
    }

    @Test
    void suppliedChainIsNotReordered() {
        assertThat(CertValidator.of(leaf).chain(root, intermediate)
                .trustAnchors(root).validate().isValid()).isFalse();
    }

    @Test
    void unrelatedTrustAnchorDoesNotAuthorizeASuppliedRoot() {
        KeyPair otherKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate otherRoot = PkiCertificate.selfSigned().subject("CN=Other Root")
                .keyPair(otherKeys).validFor(Duration.ofDays(30)).isCA(true).build();
        assertThat(CertValidator.of(leaf).chain(intermediate, root)
                .trustAnchors(otherRoot).validate().isValid()).isFalse();
    }

    @Test
    void rejectsPathLengthViolationBelowIntermediate() {
        KeyPair subCaKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate subCa = PkiCertificate.signed().subject("CN=Forbidden Sub CA")
                .keyPair(subCaKeys).issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(30)).pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN).build();
        X509Certificate below = leafIssuedBy(subCa, subCaKeys.getPrivate(), "below.example.com");
        ValidationResult result = CertValidator.of(below).chain(subCa, intermediate, root)
                .trustAnchors(root).validate();
        assertRejected(result, "PATH_TOO_LONG");
    }

    @Test
    void rejectsIssuerWithoutKeyCertSign() {
        X509Certificate wrongUsage = PkiCertificate.signed().subject("CN=Wrong Usage CA")
                .keyPair(intermediateKeys).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30)).pathLength(0)
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE).build();
        X509Certificate below = leafIssuedBy(wrongUsage, intermediateKeys.getPrivate(), "usage.example.com");
        assertRejected(CertValidator.of(below).chain(wrongUsage, root)
                .trustAnchors(root).validate(), "INVALID_KEY_USAGE");
    }

    @Test
    void enforcesDnsNameConstraints() throws Exception {
        NameConstraints constraints = new NameConstraints(
                new GeneralSubtree[] {new GeneralSubtree(new GeneralName(
                        GeneralName.dNSName, ".example.com"))}, null);
        X509Certificate constrained = withExtension(intermediate, Extension.nameConstraints,
                true, constraints, rootKeys.getPrivate());
        assertThat(CertValidator.of(leaf).chain(constrained, root)
                .trustAnchors(root).validate().isValid()).isTrue();
        X509Certificate outside = leafIssuedBy(constrained, intermediateKeys.getPrivate(), "outside.example.net");
        assertRejected(CertValidator.of(outside).chain(constrained, root)
                .trustAnchors(root).validate(), "INVALID_NAME");
    }

    @Test
    void rejectsUnknownCriticalExtensionOnLeafAndIntermediate() throws Exception {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1");
        X509Certificate criticalLeaf = withExtension(leaf, oid, true,
                new DERUTF8String("unsupported"), intermediateKeys.getPrivate());
        assertRejected(CertValidator.of(criticalLeaf).chain(intermediate, root)
                .trustAnchors(root).validate(), "UNRECOGNIZED_CRITICAL_EXTENSION");
        X509Certificate criticalCa = withExtension(intermediate, oid, true,
                new DERUTF8String("unsupported"), rootKeys.getPrivate());
        assertRejected(CertValidator.of(leaf).chain(criticalCa, root)
                .trustAnchors(root).validate(), "UNRECOGNIZED_CRITICAL_EXTENSION");
        X509Certificate nonCriticalLeaf = withExtension(leaf, oid, false,
                new DERUTF8String("optional"), intermediateKeys.getPrivate());
        assertThat(CertValidator.of(nonCriticalLeaf).chain(intermediate, root)
                .trustAnchors(root).validate().isValid()).isTrue();
    }

    @Test
    void explicitAnchorIsNotValidatedAsAPathCertificate() throws Exception {
        Instant now = Instant.now();
        X509Certificate expiredRoot = PkiCertificate.selfSigned().subject("CN=Expired Anchor")
                .keyPair(rootKeys).validFrom(now.minus(Duration.ofDays(10)))
                .validUntil(now.minus(Duration.ofDays(1))).isCA(true).build();
        expiredRoot = withExtension(expiredRoot, new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.2"),
                true, new DERUTF8String("anchor-only"), rootKeys.getPrivate());
        X509Certificate currentLeaf = leafIssuedBy(expiredRoot, rootKeys.getPrivate(), "anchor.example.com");
        ValidationResult included = CertValidator.of(currentLeaf).chain(expiredRoot)
                .trustAnchors(expiredRoot).validate();
        ValidationResult omitted = CertValidator.of(currentLeaf).trustAnchors(expiredRoot).validate();
        assertThat(included.isValid()).isTrue();
        assertThat(included.isExpired()).isFalse();
        assertThat(omitted.isValid()).isTrue();
    }

    @Test
    void explicitAnchorDoesNotRequireASelfSignature() {
        KeyPair otherKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate sameDnNewKey = PkiCertificate.signed().subject("CN=PKIX Root")
                .keyPair(otherKeys).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30)).isCA(true).build();
        X509Certificate below = leafIssuedBy(sameDnNewKey, otherKeys.getPrivate(), "rollover.example.com");
        assertThat(CertValidator.of(below).chain(sameDnNewKey)
                .trustAnchors(sameDnNewKey).validate().isValid()).isTrue();
    }

    @Test
    void explicitlyTrustedEndEntityRemainsAValidDirectTrustTarget() {
        assertThat(CertValidator.of(leaf).trustAnchors(leaf).validate().isValid()).isTrue();
    }

    @Test
    void reportsExpiredAndFutureCertificatesAtTheRequestedTime() {
        Instant start = Instant.now().minus(Duration.ofDays(60));
        X509Certificate past = PkiCertificate.signed().subject("CN=Archived")
                .keyPair(leafKeys).issuer(root, rootKeys.getPrivate())
                .validFrom(start).validUntil(start.plus(Duration.ofDays(30))).build();
        assertThat(CertValidator.of(past).trustAnchors(root).at(start.plusSeconds(10))
                .validate().isValid()).isTrue();
        ValidationResult expired = CertValidator.of(past).trustAnchors(root).validate();
        assertThat(expired.isExpired()).isTrue();
        assertThat(expired.isTrusted()).isTrue();
        assertRejected(expired, "EXPIRED");
        ValidationResult future = CertValidator.of(past).trustAnchors(root).at(start.minusSeconds(10))
                .validate();
        assertThat(future.isNotYetValid()).isTrue();
        assertRejected(future, "NOT_YET_VALID");
    }

    @Test
    void nullTrustAnchorCannotMasqueradeAsConfiguredTrust() {
        CertValidator validator = CertValidator.of(leaf).chain(intermediate, root);
        assertThatNullPointerException().isThrownBy(() -> validator.trustAnchors((X509Certificate) null));
        assertThatNullPointerException().isThrownBy(() -> validator.trustAnchors(Arrays.asList(root, null)));
        assertThat(validator.validate().isTrusted()).isFalse();
    }

    private static X509Certificate leafIssuedBy(X509Certificate issuer, PrivateKey signer, String dns) {
        return PkiCertificate.signed().subject("CN=" + dns).keyPair(leafKeys)
                .issuer(issuer, signer).validFor(Duration.ofDays(30))
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE).san(s -> s.dns(dns)).build();
    }

    private static X509Certificate withExtension(X509Certificate source, ASN1ObjectIdentifier oid,
                                                  boolean critical, ASN1Encodable value,
                                                  PrivateKey signer) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new JcaX509CertificateHolder(source));
        builder.addExtension(oid, critical, value);
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signer)));
    }

    private static void assertRejected(ValidationResult result, String code) {
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).extracting(e -> e.code().name()).contains(code);
    }
}
