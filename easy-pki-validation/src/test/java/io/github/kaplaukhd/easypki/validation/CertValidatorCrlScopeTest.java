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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import io.github.kaplaukhd.easypki.*;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CertValidatorCrlScopeTest {
    private static final KeyPair KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT = PkiCertificate.selfSigned().subject("CN=Scope Root")
            .keyPair(KEYS).isCA(true).validFor(Duration.ofDays(2)).build();
    private static final X509Certificate LEAF = PkiCertificate.signed().subject("CN=Leaf")
            .keyPair(PkiKeys.ec(Curve.P_256)).issuer(ROOT, KEYS.getPrivate())
            .validFor(Duration.ofDays(1)).build();

    @ParameterizedTest
    @ValueSource(strings = {"delta", "indirect", "ca-only", "user-only", "reasons", "named", "empty-idp",
            "unknown-critical", "entry-critical", "entry-issuer"})
    void unsupportedEvidenceCannotEstablishGoodStatus(String type) throws Exception {
        var result = validate(crl(type));
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).anyMatch(e -> e.code() == ValidationError.Code.REVOCATION_UNKNOWN);
        assertThat(result.getErrors()).anySatisfy(e -> {
            assertThat(e.code()).isEqualTo(ValidationError.Code.UNSUPPORTED_CRL);
            assertThat(e.message()).contains("static CRL");
        });
    }

    @Test
    void completeCrlWithNoncriticalUnknownExtensionIsUsable() throws Exception {
        assertThat(validate(crl("noncritical")).isValid()).isTrue();
    }

    @Test
    void unsupportedCandidateCanRecoverThroughCompleteCrl() throws Exception {
        var result = validate(crl("delta"), crl("complete"));
        assertThat(result.isValid()).isTrue();
        assertThat(result.getWarnings()).anyMatch(e -> e.code() == ValidationError.Code.UNSUPPORTED_CRL);
    }

    @Test
    void fullCrlRevocationRemainsFatal() throws Exception {
        var result = validate(crl("revoked"), crl("complete"));
        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void downloadedUnsupportedCrlCannotEstablishGoodAndCanFallBack(boolean fallback) throws Exception {
        var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        byte[] delta = crl("delta").getEncoded();
        byte[] complete = crl("complete").getEncoded();
        server.createContext("/delta", exchange -> {
            exchange.sendResponseHeaders(200, delta.length);
            try (var out = exchange.getResponseBody()) { out.write(delta); }
        });
        server.createContext("/complete", exchange -> {
            exchange.sendResponseHeaders(200, complete.length);
            try (var out = exchange.getResponseBody()) { out.write(complete); }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            var builder = PkiCertificate.signed().subject("CN=Downloaded CRL")
                    .keyPair(PkiKeys.ec(Curve.P_256)).issuer(ROOT, KEYS.getPrivate())
                    .validFor(Duration.ofHours(1)).crlDistributionPoint(url + "/delta");
            if (fallback) builder.crlDistributionPoint(url + "/complete");
            var result = CertValidator.of(builder.build()).trustAnchors(ROOT).crl(c -> c.autoFetch()).validate();
            assertThat(result.isValid()).isEqualTo(fallback);
            assertThat(fallback ? result.getWarnings() : result.getErrors()).anySatisfy(e -> {
                assertThat(e.code()).isEqualTo(ValidationError.Code.UNSUPPORTED_CRL);
                assertThat(e.message()).contains(url + "/delta");
            });
        } finally { server.stop(0); }
    }

    @Test
    void issuedCrlUsesTheIssuerCertificateSki() throws Exception {
        var principal = ROOT.getSubjectX500Principal();
        byte[] custom = {1, 3, 5, 7, 9};
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(principal,
                BigInteger.valueOf(50), Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plusSeconds(86400)), principal, KEYS.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(custom));
        var issuer = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(KEYS.getPrivate())));
        var crl = PkiCrl.issued().issuer(issuer, KEYS.getPrivate()).nextUpdate(Duration.ofHours(1)).build();
        var extension = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                crl.getExtensionValue(Extension.authorityKeyIdentifier.getId())).getOctets();
        assertThat(AuthorityKeyIdentifier.getInstance(extension).getKeyIdentifierOctets()).isEqualTo(custom);
        crl.verify(KEYS.getPublic());
    }

    private static ValidationResult validate(X509CRL... crls) {
        return CertValidator.of(LEAF).trustAnchors(ROOT).crl(crls).validate();
    }

    private static X509CRL crl(String type) throws Exception {
        var b = new X509v2CRLBuilder(X500Name.getInstance(ROOT.getSubjectX500Principal().getEncoded()),
                Date.from(Instant.now().minusSeconds(10)));
        b.setNextUpdate(Date.from(Instant.now().plusSeconds(3600)));
        if (type.equals("delta")) b.addExtension(Extension.deltaCRLIndicator, true, new ASN1Integer(1));
        if (java.util.Set.of("indirect", "ca-only", "user-only", "reasons", "named", "empty-idp").contains(type)) {
            var name = type.equals("named") ? new DistributionPointName(new GeneralNames(
                    new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.test/partition.crl"))) : null;
            b.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(name,
                    type.equals("user-only"), type.equals("ca-only"), type.equals("reasons")
                    ? new ReasonFlags(ReasonFlags.keyCompromise) : null, type.equals("indirect"), false));
        }
        if (type.equals("unknown-critical") || type.equals("noncritical")) {
            b.addExtension(new ASN1ObjectIdentifier("1.2.3.4.5"), type.equals("unknown-critical"), DERNull.INSTANCE);
        }
        if (type.equals("entry-critical") || type.equals("entry-issuer")) {
            var extensions = new ExtensionsGenerator();
            if (type.equals("entry-critical")) extensions.addExtension(new ASN1ObjectIdentifier("1.2.3.4.6"), true, DERNull.INSTANCE);
            else extensions.addExtension(Extension.certificateIssuer, false, new GeneralNames(
                    new GeneralName(X500Name.getInstance(ROOT.getSubjectX500Principal().getEncoded()))));
            b.addCRLEntry(LEAF.getSerialNumber().add(BigInteger.ONE), new Date(), extensions.generate());
        }
        if (type.equals("revoked")) b.addCRLEntry(LEAF.getSerialNumber(), new Date(), 1);
        return new JcaX509CRLConverter().getCRL(b.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .build(KEYS.getPrivate())));
    }
}
