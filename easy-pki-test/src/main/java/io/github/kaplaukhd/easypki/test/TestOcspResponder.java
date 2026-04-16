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
package io.github.kaplaukhd.easypki.test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Loopback OCSP responder backed by a {@link TestPki}.
 *
 * <p>Serves a single endpoint at {@code /ocsp} that accepts standard OCSP
 * POST requests, signs responses with the PKI's effective issuer key, and
 * reports GOOD for unknown serials and REVOKED (with the recorded reason
 * and time) for serials that have been registered as revoked via
 * {@link TestPki#revoke(java.security.cert.X509Certificate,
 * RevocationReason)}. Nonce extensions are echoed back when present.
 *
 * <p>Listens on a random port on {@code 127.0.0.1}. Close the instance (or
 * use try-with-resources) to stop the embedded server.
 */
public final class TestOcspResponder implements AutoCloseable {

    private final TestPki pki;
    private final HttpServer server;
    private final String url;
    private final AtomicInteger requestCount = new AtomicInteger();

    TestOcspResponder(TestPki pki) throws IOException {
        this.pki = pki;
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/ocsp", new Handler());
        this.server.start();
        this.url = "http://127.0.0.1:" + server.getAddress().getPort() + "/ocsp";
    }

    /** Absolute URL of the responder — suitable for embedding as an AIA OCSP entry. */
    public String getUrl() {
        return url;
    }

    /** Number of OCSP requests served so far. */
    public int getRequestCount() {
        return requestCount.get();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private final class Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            requestCount.incrementAndGet();
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                OCSPReq req = new OCSPReq(body);

                X509CertificateHolder issuerHolder =
                        new JcaX509CertificateHolder(pki.getIssuerCa());

                BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                        new RespID(issuerHolder.getSubject()));

                for (Req single : req.getRequestList()) {
                    CertificateID id = single.getCertID();
                    TestPki.RevocationEntry entry = pki.revocationOf(id.getSerialNumber());
                    CertificateStatus status = (entry == null)
                            ? CertificateStatus.GOOD
                            : new RevokedStatus(
                                    Date.from(entry.revokedAt()),
                                    entry.reason().crlReasonCode());
                    builder.addResponse(id, status);
                }

                Extension reqNonce =
                        req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (reqNonce != null) {
                    byte[] nonceBytes =
                            ASN1OctetString.getInstance(reqNonce.getParsedValue()).getOctets();
                    Extension respNonce = new Extension(
                            OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                            new DEROctetString(nonceBytes).getEncoded());
                    builder.setResponseExtensions(new Extensions(respNonce));
                }

                String sigAlg = pki.getIssuerPrivateKey().getAlgorithm().equals("EC")
                        ? "SHA256withECDSA"
                        : "SHA256withRSA";
                BasicOCSPResp basic = builder.build(
                        new JcaContentSignerBuilder(sigAlg).build(pki.getIssuerPrivateKey()),
                        new X509CertificateHolder[]{issuerHolder},
                        new Date());

                OCSPResp ocspResp = new OCSPRespBuilder()
                        .build(OCSPRespBuilder.SUCCESSFUL, basic);
                byte[] respBytes = ocspResp.getEncoded();

                exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, respBytes.length);
                exchange.getResponseBody().write(respBytes);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        }
    }
}
