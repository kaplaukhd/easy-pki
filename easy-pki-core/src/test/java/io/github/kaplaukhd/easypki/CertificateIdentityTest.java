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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CertificateIdentityTest {
    private static final KeyPair ISSUER_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair SUBJECT_KEYS = PkiKeys.ec(Curve.P_256);

    @ParameterizedTest
    @ValueSource(strings = {"CN=host,O=Acme,C=US", "CN=Doe\\, Jane+UID=42,O=Acme,C=US",
            "CN=\\#literal,O=Acme", "CN=Тест,O=Компания,C=RU", "CN=single"})
    void stringSubjectsFollowJcaRdnOrder(String dn) {
        X509Certificate root = root(dn);
        X509Certificate issued = PkiCertificate.signed().subject(dn).keyPair(SUBJECT_KEYS)
                .issuer(root, ISSUER_KEYS.getPrivate()).validFor(Duration.ofDays(1)).build();
        assertThat(root.getSubjectX500Principal()).isEqualTo(new X500Principal(dn));
        assertThat(issued.getSubjectX500Principal()).isEqualTo(new X500Principal(dn));
        assertThat(issued.getIssuerX500Principal().getEncoded())
                .isEqualTo(root.getSubjectX500Principal().getEncoded());
    }

    @Test
    void fluentOrderAndLiteralValuesAgreeWithJca() {
        X509Certificate certificate = PkiCertificate.selfSigned()
                .subject(d -> d.cn("Doe, Jane+Admin").o("Acme").c("US"))
                .keyPair(ISSUER_KEYS).validFor(Duration.ofDays(1)).build();
        assertThat(certificate.getSubjectX500Principal())
                .isEqualTo(new X500Principal("CN=Doe\\, Jane\\+Admin,O=Acme,C=US"));
    }

    @Test
    void sameNameSignedByAnotherKeyIsNotSelfSigned() {
        X509Certificate issuer = root("CN=Rollover");
        X509Certificate rollover = PkiCertificate.signed().subject("CN=Rollover")
                .keyPair(SUBJECT_KEYS).issuer(issuer, ISSUER_KEYS.getPrivate())
                .validFor(Duration.ofDays(1)).build();
        assertThat(PkiCertInfo.of(rollover).isSelfSigned()).isFalse();
        assertThat(PkiCertInfo.of(issuer).isSelfSigned()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void authorityIdentifierUsesIssuerSkiOrDocumentedFallback(boolean withSki) throws Exception {
        byte[] customSki = {9, 8, 7, 6, 5};
        X500Principal name = new X500Principal("CN=External,O=Acme");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plusSeconds(86400)),
                name, ISSUER_KEYS.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        if (withSki) builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(customSki));
        X509Certificate issuer = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ISSUER_KEYS.getPrivate())));
        X509Certificate leaf = PkiCertificate.signed().subject("CN=Leaf").keyPair(SUBJECT_KEYS)
                .issuer(issuer, ISSUER_KEYS.getPrivate()).validFor(Duration.ofHours(1)).build();
        var aki = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(
                leaf.getExtensionValue(Extension.authorityKeyIdentifier.getId())).getOctets());
        byte[] actual = aki.getKeyIdentifierOctets();
        assertThat(aki.getAuthorityCertIssuer()).isNull();
        assertThat(aki.getAuthorityCertSerialNumber()).isNull();
        byte[] expected = withSki ? customSki : new JcaX509ExtensionUtils()
                .createSubjectKeyIdentifier(ISSUER_KEYS.getPublic()).getKeyIdentifier();
        assertThat(actual).isEqualTo(expected);
        leaf.verify(issuer.getPublicKey());
    }

    @Test
    void principalInputPreservesExactDerForBothBuilders() throws Exception {
        var name = new org.bouncycastle.asn1.x500.X500Name(new org.bouncycastle.asn1.x500.RDN[]{
                new org.bouncycastle.asn1.x500.RDN(org.bouncycastle.asn1.x500.style.BCStyle.O,
                        new org.bouncycastle.asn1.DERUTF8String("Acme")),
                new org.bouncycastle.asn1.x500.RDN(org.bouncycastle.asn1.x500.style.BCStyle.CN,
                        new org.bouncycastle.asn1.DERUTF8String("Exact"))});
        var principal = new X500Principal(name.getEncoded());
        var issuer = PkiCertificate.selfSigned().subject(principal).keyPair(ISSUER_KEYS)
                .validFor(Duration.ofDays(1)).build();
        var leaf = PkiCertificate.signed().subject(principal).keyPair(SUBJECT_KEYS)
                .issuer(issuer, ISSUER_KEYS.getPrivate()).validFor(Duration.ofHours(1)).build();
        assertThat(issuer.getSubjectX500Principal().getEncoded()).isEqualTo(principal.getEncoded());
        assertThat(leaf.getSubjectX500Principal().getEncoded()).isEqualTo(principal.getEncoded());
    }

    @ParameterizedTest
    @ValueSource(strings = {"#literal", " leading ", "back\\slash", "plus+comma,equals=", "quote\"value"})
    void fluentValuesAreLiteralsNotDnSyntax(String value) {
        var cert = PkiCertificate.selfSigned().subject(d -> d.cn(value).o("Acme"))
                .keyPair(ISSUER_KEYS).validFor(Duration.ofDays(1)).build();
        assertThat(cert.getSubjectX500Principal()).isEqualTo(new X500Principal(
                "CN=" + javax.naming.ldap.Rdn.escapeValue(value) + ",O=Acme"));
    }

    @Test
    void selfIssuedSelfSignedAndOrdinaryIssuedHaveDistinctMeanings() throws Exception {
        var issuer = root("CN=Same");
        var rollover = PkiCertificate.signed().subject("CN=Same").keyPair(SUBJECT_KEYS)
                .issuer(issuer, ISSUER_KEYS.getPrivate()).validFor(Duration.ofHours(1)).build();
        assertThat(PkiCertInfo.of(rollover).isSelfIssued()).isTrue();
        assertThat(PkiCertInfo.of(rollover).isSelfSigned()).isFalse();
        var otherName = PkiCertificate.signed().subject("CN=Different").keyPair(ISSUER_KEYS)
                .issuer(issuer, ISSUER_KEYS.getPrivate()).validFor(Duration.ofHours(1)).build();
        otherName.verify(otherName.getPublicKey());
        assertThat(PkiCertInfo.of(otherName).isSelfIssued()).isFalse();
        assertThat(PkiCertInfo.of(otherName).isSelfSigned()).isFalse();
        byte[] tampered = issuer.getEncoded();
        tampered[tampered.length - 1] ^= 1;
        var badSignature = PkiCertificates.fromDer(tampered);
        assertThat(PkiCertInfo.of(badSignature).isSelfIssued()).isTrue();
        assertThat(PkiCertInfo.of(badSignature).isSelfSigned()).isFalse();
        var expired = PkiCertificate.selfSigned().subject("CN=Expired").keyPair(ISSUER_KEYS)
                .validFrom(Instant.now().minus(Duration.ofDays(2)))
                .validUntil(Instant.now().minus(Duration.ofDays(1))).build();
        assertThat(PkiCertInfo.of(expired).isSelfSigned()).isTrue();
    }

    private static X509Certificate root(String name) {
        return PkiCertificate.selfSigned().subject(name).keyPair(ISSUER_KEYS)
                .isCA(true).validFor(Duration.ofDays(2)).build();
    }
}
