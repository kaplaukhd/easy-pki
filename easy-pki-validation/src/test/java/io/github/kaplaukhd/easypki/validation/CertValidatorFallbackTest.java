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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CertValidatorFallbackTest {
    private static KeyPair rootKeys;
    private static X509Certificate root;
    private HttpServer server;
    private AtomicInteger secondRequests;

    @BeforeAll
    static void root() {
        rootKeys = PkiKeys.ec(Curve.P_256);
        root = PkiCertificate.selfSigned().subject("CN=Fallback root").keyPair(rootKeys)
                .isCA(true).validFor(Duration.ofDays(365))
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
    }

    @BeforeEach
    void server() throws Exception {
        secondRequests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void unavailableOcspFallsBackToGoodCrl() {
        server.createContext("/ocsp", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        X509Certificate leaf = leaf();
        ValidationResult result = validator(leaf).ocsp(o -> o.url(url("/ocsp")))
                .crl(crl()).validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getErrors()).isEmpty();
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.OCSP_UNAVAILABLE);
        assertThat(result.getWarnings().get(0).message()).contains(url("/ocsp"));
    }

    @Test
    void unknownOcspFallsBackToGoodCrl() {
        ocsp(new UnknownStatus());
        ValidationResult result = validator(leaf()).ocsp(o -> o.url(url("/ocsp")).nonce(false))
                .crl(crl()).validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.REVOCATION_UNKNOWN);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http", "malformed", "expired", "future", "wrong-key", "wrong-issuer"})
    void invalidFirstDistributionPointDoesNotPoisonSecond(String failure) {
        X509Certificate leaf = leaf();
        if (failure.equals("http")) {
            server.createContext("/first", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        } else if (failure.equals("malformed")) {
            respond("/first", new byte[]{1, 2, 3});
        } else {
            respond("/first", encoded(badCrl(failure)));
        }
        respond("/second", encoded(crl()));
        ValidationResult result = validator(leaf).crl(c -> c.autoFetch()).validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getErrors()).isEmpty();
        assertThat(secondRequests.get()).isEqualTo(1);
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.CRL_UNAVAILABLE);
        assertThat(result.getWarnings().get(0).message()).contains(url("/first"));
    }

    @Test
    void invalidStaticCrlDoesNotPoisonLaterGoodCandidate() {
        ValidationResult result = validator(leaf()).crl(badCrl("expired"), crl()).validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getWarnings()).extracting(ValidationError::code)
                .containsExactly(ValidationError.Code.CRL_UNAVAILABLE);
    }

    @Test
    void definitiveOcspRevocationDoesNotFallBackToGoodCrl() {
        ocsp(new RevokedStatus(Date.from(Instant.now().minusSeconds(60)), 1));
        respond("/first", encoded(crl()));
        respond("/second", encoded(crl()));
        ValidationResult result = validator(leaf()).ocsp(o -> o.url(url("/ocsp")).nonce(false))
                .crl(c -> c.autoFetch()).validate();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.isValid()).isFalse();
        assertThat(secondRequests.get()).isZero();
    }

    @Test
    void definitiveCrlRevocationDoesNotFallBackToGoodCandidate() {
        X509Certificate leaf = leaf();
        respond("/first", encoded(PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .revoke(leaf, RevocationReason.KEY_COMPROMISE).build()));
        respond("/second", encoded(crl()));
        ValidationResult result = validator(leaf).crl(c -> c.autoFetch()).validate();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.isValid()).isFalse();
        assertThat(secondRequests.get()).isZero();
    }

    @Test
    void exhaustedOcspAndCrlAttemptsRemainFatal() {
        server.createContext("/ocsp", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        respond("/first", new byte[]{0});
        respond("/second", new byte[]{0});
        ValidationResult result = validator(leaf()).ocsp(o -> o.url(url("/ocsp")))
                .crl(c -> c.autoFetch()).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).extracting(ValidationError::code).contains(
                ValidationError.Code.OCSP_UNAVAILABLE, ValidationError.Code.CRL_UNAVAILABLE,
                ValidationError.Code.REVOCATION_UNKNOWN);
        assertThat(result.getWarnings()).isEmpty();
    }

    @Test
    void recoveredWarningsAreImmutableAndDoNotLeakIntoTheNextValidation() {
        server.createContext("/ocsp", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        CertValidator validator = validator(leaf()).ocsp(o -> o.url(url("/ocsp")).nonce(false)).crl(crl());
        ValidationResult first = validator.validate();
        server.removeContext("/ocsp");
        ocsp(CertificateStatus.GOOD);
        ValidationResult second = validator.validate();

        assertThat(first.isValid()).isTrue();
        assertThat(first.getWarnings()).hasSize(1);
        assertThatThrownBy(() -> first.getWarnings().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(second.isValid()).isTrue();
        assertThat(second.getWarnings()).isEmpty();
        assertThat(first.getWarnings()).hasSize(1);
    }

    @Test
    void successfulIntermediateCheckCannotEraseAnExhaustedLeafFailure() {
        server.createContext("/ocsp", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        KeyPair caKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate ca = PkiCertificate.signed().subject("CN=Second CA")
                .publicKey(caKeys.getPublic()).issuer(root, rootKeys.getPrivate())
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .validFor(Duration.ofDays(90)).build();
        X509Certificate leaf = PkiCertificate.signed().subject("CN=No leaf CRL")
                .publicKey(PkiKeys.ec(Curve.P_256).getPublic()).issuer(ca, caKeys.getPrivate())
                .validFor(Duration.ofDays(30)).build();
        ValidationResult result = CertValidator.of(leaf).chain(ca).trustAnchors(root)
                .ocsp(o -> o.url(url("/ocsp"))).crl(crl()).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).extracting(ValidationError::code)
                .contains(ValidationError.Code.OCSP_UNAVAILABLE, ValidationError.Code.REVOCATION_UNKNOWN);
    }

    private CertValidator validator(X509Certificate leaf) {
        return CertValidator.of(leaf).chain(root).trustAnchors(root);
    }

    private X509Certificate leaf() {
        return PkiCertificate.signed().subject("CN=Fallback leaf")
                .publicKey(PkiKeys.ec(Curve.P_256).getPublic()).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30)).crlDistributionPoint(url("/first")).crlDistributionPoint(url("/second")).build();
    }

    private static X509CRL crl() {
        return PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate()).build();
    }

    private static X509CRL badCrl(String failure) {
        Instant now = Instant.now();
        if (failure.equals("expired")) return PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .thisUpdate(now.minus(Duration.ofDays(2))).nextUpdate(now.minus(Duration.ofDays(1))).build();
        if (failure.equals("future")) return PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(root, rootKeys.getPrivate())
                .thisUpdate(now.plus(Duration.ofDays(1))).nextUpdate(now.plus(Duration.ofDays(2))).build();
        KeyPair otherKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate other = PkiCertificate.selfSigned()
                .subject(failure.equals("wrong-key") ? "CN=Fallback root" : "CN=Other root")
                .keyPair(otherKeys).isCA(true).validFor(Duration.ofDays(365)).build();
        return PkiCrl.issued().nextUpdate(Duration.ofHours(24)).issuer(other, otherKeys.getPrivate()).build();
    }

    private String url(String path) { return "http://127.0.0.1:" + server.getAddress().getPort() + path; }

    private void respond(String path, byte[] body) {
        server.createContext(path, exchange -> {
            if (path.equals("/second")) secondRequests.incrementAndGet();
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) { out.write(body); }
            exchange.close();
        });
    }

    private void ocsp(CertificateStatus status) {
        server.createContext("/ocsp", exchange -> {
            try {
                OCSPReq request = new OCSPReq(exchange.getRequestBody().readAllBytes());
                BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                        SubjectPublicKeyInfo.getInstance(rootKeys.getPublic().getEncoded()),
                        new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1));
                builder.addResponse(request.getRequestList()[0].getCertID(), status,
                        Date.from(Instant.now().minusSeconds(30)), Date.from(Instant.now().plusSeconds(300)), null);
                BasicOCSPResp basic = builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(rootKeys.getPrivate()),
                        new org.bouncycastle.cert.X509CertificateHolder[]{new JcaX509CertificateHolder(root)}, new Date());
                byte[] body = new OCSPRespBuilder().build(OCSPResp.SUCCESSFUL, basic).getEncoded();
                exchange.sendResponseHeaders(200, body.length);
                try (var out = exchange.getResponseBody()) { out.write(body); }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally { exchange.close(); }
        });
    }

    private static byte[] encoded(X509CRL crl) {
        try { return crl.getEncoded(); }
        catch (java.security.cert.CRLException e) { throw new IllegalStateException(e); }
    }
}
