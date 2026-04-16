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
package io.github.kaplaukhd.easypki.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

class EasyPkiHealthIndicatorTest {

    private static final Duration WARN_BEFORE = Duration.ofDays(30);

    @Test
    void healthyBundleReportsUp() {
        Pkcs12Bundle bundle = bundle(newCert("CN=ok", Duration.ofDays(365)));
        EasyPkiHealthIndicator indicator = new EasyPkiHealthIndicator(
                Optional.of(bundle), Optional.empty(), WARN_BEFORE);

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
                .containsKey(EasyPkiAutoConfiguration.TRUST_STORE_BEAN + "[0]");
        @SuppressWarnings("unchecked")
        Map<String, Object> detail = (Map<String, Object>) health.getDetails()
                .get(EasyPkiAutoConfiguration.TRUST_STORE_BEAN + "[0]");
        assertThat(detail).containsEntry("status", "OK");
        assertThat(detail.get("subject").toString()).contains("CN=ok");
    }

    @Test
    void expiringCertStaysUpButFlagged() {
        X509Certificate cert = newCert("CN=soon", Duration.ofDays(10));
        EasyPkiHealthIndicator indicator = new EasyPkiHealthIndicator(
                Optional.of(bundle(cert)), Optional.empty(), WARN_BEFORE);

        Health health = indicator.health();
        @SuppressWarnings("unchecked")
        Map<String, Object> detail = (Map<String, Object>) health.getDetails()
                .get(EasyPkiAutoConfiguration.TRUST_STORE_BEAN + "[0]");

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(detail).containsEntry("status", "EXPIRING");
        assertThat(((Number) detail.get("daysLeft")).longValue()).isBetween(9L, 10L);
    }

    @Test
    void expiredCertTurnsStatusDown() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate expired = PkiCertificate.selfSigned()
                .subject("CN=expired")
                .keyPair(keys)
                .validFrom(Instant.now().minus(Duration.ofDays(30)))
                .validUntil(Instant.now().minus(Duration.ofDays(1)))
                .build();
        EasyPkiHealthIndicator indicator = new EasyPkiHealthIndicator(
                Optional.of(bundle(expired)), Optional.empty(), WARN_BEFORE);

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        @SuppressWarnings("unchecked")
        Map<String, Object> detail = (Map<String, Object>) health.getDetails()
                .get(EasyPkiAutoConfiguration.TRUST_STORE_BEAN + "[0]");
        assertThat(detail).containsEntry("status", "EXPIRED");
    }

    @Test
    void noStoresProducesEmptyDetailsUp() {
        EasyPkiHealthIndicator indicator = new EasyPkiHealthIndicator(
                Optional.empty(), Optional.empty(), WARN_BEFORE);

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).isEmpty();
    }

    @Test
    void bothStoresAppearInDetails() {
        Pkcs12Bundle trust = bundle(newCert("CN=root", Duration.ofDays(365)));
        Pkcs12Bundle key = bundle(newCert("CN=server", Duration.ofDays(60)));
        EasyPkiHealthIndicator indicator = new EasyPkiHealthIndicator(
                Optional.of(trust), Optional.of(key), WARN_BEFORE);

        Health health = indicator.health();

        assertThat(health.getDetails())
                .containsKey(EasyPkiAutoConfiguration.TRUST_STORE_BEAN + "[0]")
                .containsKey(EasyPkiAutoConfiguration.KEY_STORE_BEAN + "[0]");
    }

    private static X509Certificate newCert(String cn, Duration validity) {
        KeyPair keys = PkiKeys.rsa(2048);
        return PkiCertificate.selfSigned()
                .subject(cn)
                .keyPair(keys)
                .validFor(validity)
                .build();
    }

    private static Pkcs12Bundle bundle(X509Certificate cert) {
        return PkiPkcs12.create()
                .certificate(cert)
                .alias("entry")
                .password("x")
                .build();
    }
}
