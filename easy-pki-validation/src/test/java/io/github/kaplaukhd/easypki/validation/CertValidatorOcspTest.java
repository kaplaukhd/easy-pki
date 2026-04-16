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

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertValidatorOcspTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair intermediateKeys;
    private X509Certificate intermediate;
    private KeyPair leafKeys;
    private X509Certificate leaf;

    private HttpServer server;
    private AtomicInteger requestCount;

    @BeforeEach
    void setUp() throws IOException {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=OCSP Root").keyPair(rootKeys)
                .validFor(Duration.ofDays(3650)).isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();

        intermediateKeys = PkiKeys.rsa(2048);
        intermediate = PkiCertificate.signed()
                .subject("CN=OCSP Intermediate")
                .publicKey(intermediateKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825))
                .pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        leafKeys = PkiKeys.rsa(2048);
        // Leaf will have AIA OCSP URL filled in per test once server is bound.

        requestCount = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private int port() {
        return server.getAddress().getPort();
    }

    private String ocspUrl() {
        return "http://127.0.0.1:" + port() + "/ocsp";
    }

    /** Issues a leaf whose AIA OCSP URL points at the embedded responder. */
    private X509Certificate issueLeaf(BigInteger serial) {
        return PkiCertificate.signed()
                .subject("CN=ocsp-leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .serialNumber(serial)
                .ocsp(ocspUrl())
                .build();
    }

    /**
     * Mounts a responder that answers every OCSP query with the supplied
     * {@link CertificateStatus} for any serial.
     */
    private void mountResponder(CertificateStatus status) {
        mountResponder((req, serial) -> status);
    }

    private void mountResponder(Responder responder) {
        server.createContext("/ocsp", new OcspResponderHandler(responder));
    }

    @Test
    void goodStatusPassesValidation() {
        leaf = issueLeaf(BigInteger.valueOf(1001));
        mountResponder(CertificateStatus.GOOD);

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .ocsp()
                .validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isRevoked()).isFalse();
        assertThat(requestCount.get()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void revokedStatusIsReported() {
        leaf = issueLeaf(BigInteger.valueOf(1002));
        Date revokedAt = new Date(System.currentTimeMillis() - Duration.ofDays(2).toMillis());
        mountResponder(new RevokedStatus(revokedAt,
                RevocationReason.KEY_COMPROMISE.crlReasonCode()));

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .ocsp()
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    @Test
    void unknownStatusYieldsRevocationUnknown() {
        leaf = issueLeaf(BigInteger.valueOf(1003));
        mountResponder(new UnknownStatus());

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .ocsp()
                .validate();

        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
    }

    @Test
    void serverDownReportsOcspUnavailable() {
        leaf = issueLeaf(BigInteger.valueOf(1004));
        server.createContext("/ocsp", exchange -> {
            requestCount.incrementAndGet();
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .ocsp(o -> o.timeout(Duration.ofSeconds(2)))
                .validate();

        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.OCSP_UNAVAILABLE));
        assertThat(result.isRevoked()).isFalse();
    }

    @Test
    void urlOverrideBeatsAiaExtension() {
        // Issue leaf without any AIA — the override URL forces the fetch.
        X509Certificate bare = PkiCertificate.signed()
                .subject("CN=no-aia")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .serialNumber(BigInteger.valueOf(1005))
                .build();

        mountResponder(CertificateStatus.GOOD);

        ValidationResult result = CertValidator.of(bare)
                .chain(intermediate, root)
                .ocsp(o -> o.url(ocspUrl()))
                .validate();

        assertThat(result.isValid()).isTrue();
    }

    @Test
    void ocspFallsBackToCrlWhenUnavailable() {
        leaf = issueLeaf(BigInteger.valueOf(1006));
        server.createContext("/ocsp", exchange -> {
            requestCount.incrementAndGet();
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });

        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.CESSATION_OF_OPERATION)
                .build();
        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .ocsp(o -> o.timeout(Duration.ofSeconds(2)))
                .crl(leafCrl, intermediateCrl)
                .validate();

        // OCSP failed, CRL took over: leaf is revoked.
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.CESSATION_OF_OPERATION);
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.OCSP_UNAVAILABLE));
    }

    @Test
    void noOcspUrlAndNoFallbackFailsCleanly() {
        X509Certificate bare = PkiCertificate.signed()
                .subject("CN=no-aia-2")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .serialNumber(BigInteger.valueOf(1007))
                .build();

        ValidationResult result = CertValidator.of(bare)
                .chain(intermediate, root)
                .ocsp()
                .validate();

        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
    }

    // ---------- embedded OCSP responder ----------

    @FunctionalInterface
    private interface Responder {
        CertificateStatus statusFor(Req req, BigInteger serial) throws Exception;
    }

    private final class OcspResponderHandler implements HttpHandler {
        private final Responder responder;

        OcspResponderHandler(Responder responder) {
            this.responder = responder;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            requestCount.incrementAndGet();
            try {
                byte[] reqBytes = exchange.getRequestBody().readAllBytes();
                OCSPReq req = new OCSPReq(reqBytes);
                X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(intermediate);

                DigestCalculatorProvider digestProv = new JcaDigestCalculatorProviderBuilder().build();
                BasicOCSPRespBuilder basicBuilder = new BasicOCSPRespBuilder(
                        new RespID(issuerHolder.getSubject()));

                for (Req single : req.getRequestList()) {
                    CertificateID id = single.getCertID();
                    CertificateStatus status = responder.statusFor(single, id.getSerialNumber());
                    basicBuilder.addResponse(id, status);
                }

                // Echo the nonce back if the client sent one.
                Extension reqNonce = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (reqNonce != null) {
                    byte[] nonceBytes = ASN1OctetString.getInstance(reqNonce.getParsedValue()).getOctets();
                    Extension respNonce = new Extension(
                            OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                            new DEROctetString(nonceBytes).getEncoded());
                    basicBuilder.setResponseExtensions(new Extensions(respNonce));
                }

                BasicOCSPResp basicResp = basicBuilder.build(
                        new JcaContentSignerBuilder("SHA256withRSA")
                                .build(intermediateKeys.getPrivate()),
                        new X509CertificateHolder[]{issuerHolder},
                        new Date());

                OCSPResp ocspResp = new OCSPRespBuilder()
                        .build(OCSPRespBuilder.SUCCESSFUL, basicResp);
                byte[] body = ocspResp.getEncoded();

                exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        }
    }
}
