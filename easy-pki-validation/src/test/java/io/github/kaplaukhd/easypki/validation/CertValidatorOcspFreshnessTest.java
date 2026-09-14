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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertValidatorOcspFreshnessTest {

    private static final Instant EVALUATION_TIME = Instant.parse("2024-06-15T12:00:00Z");
    private static KeyPair issuerKeys;
    private static X509Certificate issuer;
    private static X509Certificate leaf;

    private final AtomicReference<Response> response = new AtomicReference<>();
    private HttpServer server;

    @BeforeAll
    static void hierarchy() {
        issuerKeys = PkiKeys.ec(Curve.P_256);
        issuer = PkiCertificate.selfSigned().subject("CN=OCSP Freshness Root")
                .keyPair(issuerKeys).isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .validFrom(Instant.parse("2020-01-01T00:00:00Z"))
                .validUntil(Instant.parse("2040-01-01T00:00:00Z")).build();
        leaf = PkiCertificate.signed().subject("CN=OCSP Freshness Leaf")
                .keyPair(PkiKeys.ec(Curve.P_256)).issuer(issuer, issuerKeys.getPrivate())
                .validFrom(Instant.parse("2020-01-01T00:00:00Z"))
                .validUntil(Instant.parse("2040-01-01T00:00:00Z")).build();
    }

    @BeforeEach
    void responder() throws IOException {
        setTimes(EVALUATION_TIME.minusSeconds(60), null, EVALUATION_TIME);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ocsp", exchange -> {
            try {
                OCSPReq request = new OCSPReq(exchange.getRequestBody().readAllBytes());
                Response current = response.get();
                JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
                BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                        new RespID(issuerHolder.getSubject()));
                builder.addResponse(request.getRequestList()[0].getCertID(), current.status(),
                        Date.from(current.thisUpdate()), current.nextUpdate() == null
                                ? null : Date.from(current.nextUpdate()), null);
                Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (nonce != null && current.echoNonce()) {
                    builder.setResponseExtensions(new Extensions(nonce));
                }
                BasicOCSPResp basic = builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(current.signingKeys().getPrivate()),
                        new X509CertificateHolder[]{issuerHolder}, Date.from(current.producedAt()));
                byte[] body = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
                exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
    }

    @AfterEach
    void stopResponder() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void defaultsAcceptFreshResponseWithoutNextUpdate() {
        assertThat(validator().validate().isValid()).isTrue();
    }

    @Test
    void defaultAgeLimitRejectsOldResponseWithoutNextUpdateAndWithoutNonce() {
        Instant old = EVALUATION_TIME.minus(Duration.ofHours(24)).minusSeconds(301);
        setTimes(old, null, old);
        assertUnavailable(validator().validate(), "maxResponseAge");
    }

    @Test
    void matchingNonceDoesNotBypassFreshness() {
        Instant old = EVALUATION_TIME.minus(Duration.ofDays(2));
        setTimes(old, null, old);
        assertUnavailable(validator().ocsp(o -> o.nonce(true)).validate(), "maxResponseAge");
    }

    @Test
    void expiredNextUpdateIsRejectedWithoutNonce() {
        setTimes(EVALUATION_TIME.minus(Duration.ofDays(2)),
                EVALUATION_TIME.minus(Duration.ofDays(1)),
                EVALUATION_TIME.minus(Duration.ofDays(2)));
        assertUnavailable(validator().validate(), "expired");
    }

    @Test
    void futureThisUpdateIsRejectedWithoutNonce() {
        setTimes(EVALUATION_TIME.plusSeconds(301), EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME);
        assertUnavailable(validator().validate(), "thisUpdate is in the future");
    }

    @Test
    void futureProducedAtIsRejectedEvenWhenSingleResponseIsFresh() {
        setTimes(EVALUATION_TIME.minusSeconds(60), EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME.plusSeconds(301));
        assertUnavailable(validator().validate(), "producedAt is in the future");
    }

    @Test
    void nextUpdateCannotPrecedeThisUpdateEvenWithinClockSkew() {
        setTimes(EVALUATION_TIME, EVALUATION_TIME.minusSeconds(1), EVALUATION_TIME);
        assertUnavailable(validator().validate(), "nextUpdate precedes thisUpdate");
    }

    @Test
    void zeroSkewAcceptsExactTimestampBoundaries() {
        setTimes(EVALUATION_TIME, EVALUATION_TIME, EVALUATION_TIME);
        assertThat(validator().ocsp(o -> o.clockSkew(Duration.ZERO)).validate().isValid()).isTrue();
    }

    @Test
    void configuredSkewAppliesToThisUpdateAndProducedAtBoundaries() {
        setTimes(EVALUATION_TIME.plusSeconds(30), EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME.plusSeconds(30));
        assertThat(validator().ocsp(o -> o.clockSkew(Duration.ofSeconds(30)))
                .validate().isValid()).isTrue();
        assertUnavailable(validator().ocsp(o -> o.clockSkew(Duration.ofSeconds(29)))
                .validate(), "thisUpdate is in the future");

        setTimes(EVALUATION_TIME, EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME.plusSeconds(30));
        assertUnavailable(validator().ocsp(o -> o.clockSkew(Duration.ofSeconds(29)))
                .validate(), "producedAt is in the future");
    }

    @Test
    void skewAllowsNextUpdateExpiryBoundaryOnly() {
        setTimes(EVALUATION_TIME.minusSeconds(600), EVALUATION_TIME.minusSeconds(300),
                EVALUATION_TIME.minusSeconds(600));
        assertThat(validator().validate().isValid()).isTrue();
        setTimes(EVALUATION_TIME.minusSeconds(600), EVALUATION_TIME.minusSeconds(301),
                EVALUATION_TIME.minusSeconds(600));
        assertUnavailable(validator().validate(), "expired");
    }

    @Test
    void configuredMaximumAgeAllowsExactAgePlusSkewOnly() {
        Instant old = EVALUATION_TIME.minus(Duration.ofHours(1)).minusSeconds(300);
        setTimes(old, null, old);
        assertThat(validator().ocsp(o -> o.maxResponseAge(Duration.ofHours(1)))
                .validate().isValid()).isTrue();
        setTimes(old.minusSeconds(1), null, old.minusSeconds(1));
        assertUnavailable(validator().ocsp(o -> o.maxResponseAge(Duration.ofHours(1)))
                .validate(), "maxResponseAge");
    }

    @Test
    void nextUpdateDeterminesExpiryWhenPresent() {
        setTimes(EVALUATION_TIME.minus(Duration.ofDays(2)), EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME.minusSeconds(60));
        assertThat(validator().ocsp(o -> o.maxResponseAge(Duration.ofMinutes(1)))
                .validate().isValid()).isTrue();
    }

    @Test
    void historicalEvaluationUsesTheRequestedInstantOnEveryValidation() {
        setTimes(EVALUATION_TIME.minusSeconds(60), EVALUATION_TIME.plusSeconds(3600),
                EVALUATION_TIME);
        CertValidator validator = validator();
        assertThat(validator.validate().isValid()).isTrue();
        assertUnavailable(validator.at(EVALUATION_TIME.plus(Duration.ofDays(1))).validate(), "expired");
        assertThat(validator.at(EVALUATION_TIME).validate().isValid()).isTrue();
    }

    @Test
    void presentDayResponseCannotEstablishHistoricalStatus() {
        Instant later = EVALUATION_TIME.plus(Duration.ofDays(1));
        setTimes(later, later.plusSeconds(3600), later);
        assertUnavailable(validator().validate(), "thisUpdate is in the future");
    }

    @Test
    void changedConfigurationTakesEffectOnReusedValidator() {
        Instant old = EVALUATION_TIME.minus(Duration.ofHours(2));
        setTimes(old, null, old);
        CertValidator validator = validator();
        assertThat(validator.validate().isValid()).isTrue();
        assertUnavailable(validator.ocsp(o -> o.maxResponseAge(Duration.ofHours(1)))
                .validate(), "maxResponseAge");
    }

    @Test
    void retainedConfigurationChangesTakeEffectOnReusedValidator() {
        Instant old = EVALUATION_TIME.minus(Duration.ofHours(2));
        setTimes(old, null, old);
        AtomicReference<OcspConfig> captured = new AtomicReference<>();
        CertValidator validator = validator().ocsp(captured::set);
        assertThat(validator.validate().isValid()).isTrue();
        captured.get().maxResponseAge(Duration.ofHours(1));
        assertUnavailable(validator.validate(), "maxResponseAge");
    }

    @Test
    void freshnessAppliesBeforeRevokedAndUnknownStatusesAreUsed() {
        Instant old = EVALUATION_TIME.minus(Duration.ofDays(2));
        for (CertificateStatus status : new CertificateStatus[]{
                new RevokedStatus(Date.from(old.minusSeconds(60)), 1), new UnknownStatus()}) {
            response.set(new Response(old, null, old, status, issuerKeys, true));
            ValidationResult result = validator().validate();
            assertUnavailable(result, "maxResponseAge");
            assertThat(result.isRevoked()).isFalse();
        }
    }

    @Test
    void freshRevokedStatusRemainsRevoked() {
        response.set(new Response(EVALUATION_TIME.minusSeconds(60), null, EVALUATION_TIME,
                new RevokedStatus(Date.from(EVALUATION_TIME.minusSeconds(3600)), 1), issuerKeys, true));
        ValidationResult result = validator().validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.isRevoked()).isTrue();
        assertThat(result.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
    }

    @Test
    void freshResponseStillRequiresIssuerSignatureAndExpectedNonce() {
        response.set(new Response(EVALUATION_TIME.minusSeconds(60), null, EVALUATION_TIME,
                CertificateStatus.GOOD, PkiKeys.ec(Curve.P_256), true));
        assertUnavailable(validator().validate(), "signature");
        response.set(new Response(EVALUATION_TIME.minusSeconds(60), null, EVALUATION_TIME,
                CertificateStatus.GOOD, issuerKeys, false));
        assertUnavailable(validator().ocsp(o -> o.nonce(true)).validate(), "nonce");
        setTimes(EVALUATION_TIME.minusSeconds(60), null, EVALUATION_TIME);
        assertThat(validator().ocsp(o -> o.nonce(true)).validate().isValid()).isTrue();
    }

    @Test
    void veryLargePolicyDurationsDoNotOverflow() {
        Instant old = EVALUATION_TIME.minus(Duration.ofDays(2));
        setTimes(old, null, old);
        assertThat(validator().ocsp(o -> o.maxResponseAge(Duration.ofSeconds(Long.MAX_VALUE))
                        .clockSkew(Duration.ofSeconds(Long.MAX_VALUE)))
                .validate().isValid()).isTrue();
    }

    @Test
    void invalidFreshnessConfigurationIsRejectedWithoutChangingPreviousValues() {
        OcspConfig config = new OcspConfig();
        assertThatNullPointerException().isThrownBy(() -> config.clockSkew(null));
        assertThatIllegalArgumentException().isThrownBy(() -> config.clockSkew(Duration.ofNanos(-1)));
        assertThatNullPointerException().isThrownBy(() -> config.maxResponseAge(null));
        assertThatIllegalArgumentException().isThrownBy(() -> config.maxResponseAge(Duration.ZERO));
        assertThatIllegalArgumentException().isThrownBy(() -> config.maxResponseAge(Duration.ofNanos(-1)));
        assertThat(config.clockSkew()).isEqualTo(Duration.ofMinutes(5));
        assertThat(config.maxResponseAge()).isEqualTo(Duration.ofHours(24));
        assertThat(config.clockSkew(Duration.ZERO)).isSameAs(config);
        assertThat(config.maxResponseAge(Duration.ofNanos(1))).isSameAs(config);
    }

    private CertValidator validator() {
        return CertValidator.of(leaf).chain(issuer).trustAnchors(issuer).at(EVALUATION_TIME)
                .ocsp(o -> o.url("http://127.0.0.1:" + server.getAddress().getPort() + "/ocsp")
                        .nonce(false).timeout(Duration.ofSeconds(2)));
    }

    private void setTimes(Instant thisUpdate, Instant nextUpdate, Instant producedAt) {
        response.set(new Response(thisUpdate, nextUpdate, producedAt,
                CertificateStatus.GOOD, issuerKeys, true));
    }

    private static void assertUnavailable(ValidationResult result, String detail) {
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).anySatisfy(error -> {
            assertThat(error.code()).isEqualTo(ValidationError.Code.OCSP_UNAVAILABLE);
            assertThat(error.message()).contains(detail);
        });
    }

    private record Response(Instant thisUpdate, Instant nextUpdate, Instant producedAt,
                            CertificateStatus status, KeyPair signingKeys, boolean echoNonce) {}
}
