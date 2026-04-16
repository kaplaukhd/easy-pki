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

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * OCSP client: builds a request for (cert, issuer), POSTs it to a responder
 * URL, parses the response and reports GOOD / REVOKED / UNKNOWN. Package-private.
 */
final class OcspClient {

    private final HttpClient client;
    private final Duration timeout;
    private final boolean nonceEnabled;
    private final SecureRandom random = new SecureRandom();

    OcspClient(Duration timeout, URI proxy, boolean nonceEnabled) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(timeout);
        if (proxy != null) {
            builder.proxy(ProxySelector.of(
                    new InetSocketAddress(proxy.getHost(), proxy.getPort())));
        }
        this.client = builder.build();
        this.timeout = timeout;
        this.nonceEnabled = nonceEnabled;
    }

    /**
     * Sends an OCSP request for the given subject certificate to the responder
     * and returns the parsed outcome. Any networking, parsing or signature
     * failure yields {@link Outcome#unavailable(String)}.
     */
    Outcome query(URI responderUrl, X509Certificate subject, X509Certificate issuer) {
        byte[] sentNonce = null;
        byte[] requestBytes;
        CertificateID certId;
        try {
            DigestCalculatorProvider digestProv =
                    new JcaDigestCalculatorProviderBuilder().build();
            certId = new CertificateID(
                    digestProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuer),
                    subject.getSerialNumber());

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            if (nonceEnabled) {
                sentNonce = new byte[16];
                random.nextBytes(sentNonce);
                // RFC 6960 §4.4.1: extnValue is an OCTET STRING whose contents
                // are an inner OCTET STRING wrapping the nonce bytes. Using the
                // byte[] overload: the bytes must be the DER encoding of the
                // inner OCTET STRING.
                Extension nonceExt = new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                        new DEROctetString(sentNonce).getEncoded());
                reqBuilder.setRequestExtensions(new Extensions(nonceExt));
            }
            OCSPReq req = reqBuilder.build();
            requestBytes = req.getEncoded();
        } catch (Exception e) {
            return Outcome.unavailable("Failed to build OCSP request: " + e.getMessage());
        }

        byte[] responseBytes;
        try {
            HttpRequest http = HttpRequest.newBuilder(responderUrl)
                    .timeout(timeout)
                    .header("Content-Type", "application/ocsp-request")
                    .header("Accept", "application/ocsp-response")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(requestBytes))
                    .build();
            HttpResponse<byte[]> resp = client.send(http, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) {
                return Outcome.unavailable(
                        "OCSP responder returned HTTP " + resp.statusCode());
            }
            responseBytes = resp.body();
        } catch (Exception e) {
            return Outcome.unavailable("OCSP HTTP request failed: " + e.getMessage());
        }

        return parse(responseBytes, certId, issuer, sentNonce);
    }

    private static Outcome parse(byte[] responseBytes,
                                 CertificateID certId,
                                 X509Certificate issuer,
                                 byte[] sentNonce) {
        try {
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                return Outcome.unavailable(
                        "OCSP response status " + ocspResp.getStatus());
            }
            BasicOCSPResp basic = (BasicOCSPResp) ocspResp.getResponseObject();
            if (basic == null) {
                return Outcome.unavailable("Empty OCSP response body");
            }

            // Signature: only the issuer-signed case is supported here. A
            // delegated OCSP responder (signed by a cert with id-kp-OCSPSigning
            // EKU issued by the issuer) is a common real-world scenario that
            // can be added later.
            if (!basic.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().build(issuer))) {
                return Outcome.unavailable("OCSP response signature does not verify");
            }

            if (sentNonce != null) {
                Extension respNonce = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (respNonce == null) {
                    return Outcome.unavailable("OCSP response lacks expected nonce");
                }
                byte[] got = ASN1OctetString.getInstance(respNonce.getParsedValue()).getOctets();
                if (!Arrays.equals(got, sentNonce)) {
                    return Outcome.unavailable("OCSP nonce mismatch");
                }
            }

            for (SingleResp single : basic.getResponses()) {
                if (!single.getCertID().equals(certId)) {
                    continue;
                }
                CertificateStatus status = single.getCertStatus();
                if (status == CertificateStatus.GOOD) {
                    return Outcome.good();
                }
                if (status instanceof RevokedStatus revoked) {
                    RevocationReason reason = revoked.hasRevocationReason()
                            ? RevocationReason.fromCode(revoked.getRevocationReason())
                            : RevocationReason.UNSPECIFIED;
                    Instant when = revoked.getRevocationTime().toInstant();
                    return Outcome.revoked(reason, when);
                }
                if (status instanceof UnknownStatus) {
                    return Outcome.unknownStatus();
                }
                return Outcome.unavailable("Unrecognised OCSP status "
                        + status.getClass().getSimpleName());
            }
            return Outcome.unavailable("OCSP response covers no matching serial");
        } catch (Exception e) {
            return Outcome.unavailable("Failed to parse OCSP response: " + e.getMessage());
        }
    }

    /** Opaque outcome of an OCSP query. */
    static final class Outcome {
        enum Kind { GOOD, REVOKED, UNKNOWN_STATUS, UNAVAILABLE }

        private final Kind kind;
        private final RevocationReason reason;
        private final Instant revokedAt;
        private final String detail;

        private Outcome(Kind kind, RevocationReason reason, Instant revokedAt, String detail) {
            this.kind = kind;
            this.reason = reason;
            this.revokedAt = revokedAt;
            this.detail = detail;
        }

        static Outcome good() {
            return new Outcome(Kind.GOOD, null, null, null);
        }

        static Outcome revoked(RevocationReason reason, Instant revokedAt) {
            return new Outcome(Kind.REVOKED, reason, revokedAt, null);
        }

        static Outcome unknownStatus() {
            return new Outcome(Kind.UNKNOWN_STATUS, null, null, null);
        }

        static Outcome unavailable(String detail) {
            return new Outcome(Kind.UNAVAILABLE, null, null, detail);
        }

        Kind kind() {
            return kind;
        }

        RevocationReason reason() {
            return reason;
        }

        Instant revokedAt() {
            return revokedAt;
        }

        String detail() {
            return detail;
        }
    }
}
