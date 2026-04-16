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
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertValidatorCrlHttpTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair intermediateKeys;
    private X509Certificate intermediate;

    private HttpServer server;
    private AtomicInteger requestCount;
    private volatile byte[] crlBody;

    @BeforeEach
    void setUp() throws IOException {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=HTTP Root").keyPair(rootKeys)
                .validFor(Duration.ofDays(3650)).isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN).build();
        intermediateKeys = PkiKeys.rsa(2048);
        intermediate = PkiCertificate.signed()
                .subject("CN=HTTP Intermediate")
                .publicKey(intermediateKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825))
                .pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        requestCount = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ca.crl", exchange -> {
            requestCount.incrementAndGet();
            byte[] body = crlBody;
            exchange.getResponseHeaders().set("Content-Type", "application/pkix-crl");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/down", exchange -> {
            requestCount.incrementAndGet();
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private int port() {
        return server.getAddress().getPort();
    }

    private X509Certificate issueLeaf(String subjectCn, String cdpPath) {
        KeyPair leafKeys = PkiKeys.rsa(2048);
        return PkiCertificate.signed()
                .subject("CN=" + subjectCn)
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .crlDistributionPoint("http://127.0.0.1:" + port() + cdpPath)
                .build();
    }

    @Test
    void nonRevokedLeafPassesWithHttpAutoFetch() throws Exception {
        X509Certificate leaf = issueLeaf("http-leaf-1", "/ca.crl");
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();
        crlBody = PkiCrls.toDer(leafCrl);

        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(intermediateCrl)                   // static for intermediate
                .crl(c -> c.autoFetch().timeout(Duration.ofSeconds(5)))
                .validate();

        assertThat(result.isValid()).isTrue();
        assertThat(result.isRevoked()).isFalse();
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void revokedLeafIsDetectedViaHttpFetchedCrl() throws Exception {
        X509Certificate leaf = issueLeaf("http-leaf-revoked", "/ca.crl");
        X509CRL leafCrl = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.KEY_COMPROMISE)
                .build();
        crlBody = PkiCrls.toDer(leafCrl);

        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(intermediateCrl)
                .crl(c -> c.autoFetch())
                .validate();

        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    @Test
    void cacheAvoidsRepeatedFetches() throws Exception {
        X509Certificate leafA = issueLeaf("http-leaf-a", "/ca.crl");
        X509CRL empty = PkiCrl.issued()
                .issuer(intermediate, intermediateKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();
        crlBody = PkiCrls.toDer(empty);

        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        CertValidator validator = CertValidator.of(leafA)
                .chain(intermediate, root)
                .crl(intermediateCrl)
                .crl(c -> c.autoFetch().cache(Duration.ofMinutes(30)));

        validator.validate();
        // A second validate() on the same validator instance reuses the fetcher
        // and its cache, so no new HTTP call should happen.
        validator.validate();

        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void serverDownReportsCrlUnavailableAndRevocationUnknown() throws Exception {
        X509Certificate leaf = issueLeaf("http-leaf-down", "/down");

        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(leaf)
                .chain(intermediate, root)
                .crl(intermediateCrl)
                .crl(c -> c.autoFetch().timeout(Duration.ofSeconds(2)))
                .validate();

        assertThat(result.isRevoked()).isFalse();
        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.CRL_UNAVAILABLE))
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
    }

    @Test
    void noCdpUrlAndNoStaticCrlProducesRevocationUnknown() throws Exception {
        // leaf has no CDP extension (we don't call crlDistributionPoint)
        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate bare = PkiCertificate.signed()
                .subject("CN=no-cdp")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        X509CRL intermediateCrl = PkiCrl.issued()
                .issuer(root, rootKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        ValidationResult result = CertValidator.of(bare)
                .chain(intermediate, root)
                .crl(intermediateCrl)
                .crl(c -> c.autoFetch())
                .validate();

        assertThat(result.getErrors())
                .anySatisfy(e -> assertThat(e.code())
                        .isEqualTo(ValidationError.Code.REVOCATION_UNKNOWN));
        assertThat(requestCount.get()).isZero();
    }
}
