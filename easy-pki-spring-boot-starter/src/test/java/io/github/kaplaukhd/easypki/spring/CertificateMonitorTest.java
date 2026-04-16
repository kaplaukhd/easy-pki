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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

class CertificateMonitorTest {

    private static final Duration CHECK_INTERVAL = Duration.ofHours(12); // irrelevant — we call check() manually
    private static final Duration WARN_BEFORE = Duration.ofDays(30);

    @Test
    void certWellWithinValidityProducesNoEvents() {
        X509Certificate cert = newCert(Duration.ofDays(365));
        RecordingPublisher publisher = new RecordingPublisher();
        CertificateMonitor monitor = new CertificateMonitor(publisher, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(cert, "server");

        monitor.check();

        assertThat(publisher.expiring).isEmpty();
        assertThat(publisher.expired).isEmpty();
    }

    @Test
    void certNearingExpiryFiresExpiringEvent() {
        X509Certificate cert = newCert(Duration.ofDays(10)); // within warn-before=30d
        RecordingPublisher publisher = new RecordingPublisher();
        CertificateMonitor monitor = new CertificateMonitor(publisher, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(cert, "server");

        monitor.check();

        assertThat(publisher.expired).isEmpty();
        assertThat(publisher.expiring).hasSize(1);
        CertExpiringEvent e = publisher.expiring.get(0);
        assertThat(e.getAlias()).isEqualTo("server");
        assertThat(e.getCertificate()).isEqualTo(cert);
        assertThat(e.getDaysLeft()).isBetween(9L, 10L);
    }

    @Test
    void expiredCertFiresExpiredEvent() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Certificate cert = PkiCertificate.selfSigned()
                .subject("CN=expired")
                .keyPair(keys)
                .validFrom(Instant.now().minus(Duration.ofDays(60)))
                .validUntil(Instant.now().minus(Duration.ofDays(1)))
                .build();
        RecordingPublisher publisher = new RecordingPublisher();
        CertificateMonitor monitor = new CertificateMonitor(publisher, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(cert, "old");

        monitor.check();

        assertThat(publisher.expiring).isEmpty();
        assertThat(publisher.expired).hasSize(1);
        assertThat(publisher.expired.get(0).getAlias()).isEqualTo("old");
    }

    @Test
    void eachEventFiresAtMostOncePerState() {
        X509Certificate cert = newCert(Duration.ofDays(10));
        RecordingPublisher publisher = new RecordingPublisher();
        CertificateMonitor monitor = new CertificateMonitor(publisher, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(cert, "server");

        monitor.check();
        monitor.check();
        monitor.check();

        assertThat(publisher.expiring).hasSize(1);
    }

    @Test
    void reRegisteringSameAliasWithDifferentCertResetsFiredState() {
        X509Certificate first = newCert(Duration.ofDays(10));
        RecordingPublisher publisher = new RecordingPublisher();
        CertificateMonitor monitor = new CertificateMonitor(publisher, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(first, "server");

        monitor.check();
        assertThat(publisher.expiring).hasSize(1);

        // Replace under same alias with a brand-new certificate — fresh firing.
        X509Certificate second = newCert(Duration.ofDays(7));
        monitor.register(second, "server");
        monitor.check();

        assertThat(publisher.expiring).hasSize(2);
    }

    @Test
    void failingListenerDoesNotBreakMonitor() {
        X509Certificate good = newCert(Duration.ofDays(10));
        X509Certificate bad = newCert(Duration.ofDays(10));

        ApplicationEventPublisher failFirst = new ApplicationEventPublisher() {
            int count = 0;

            @Override
            public void publishEvent(Object event) {
                count++;
                if (count == 1) {
                    throw new IllegalStateException("listener blew up");
                }
            }
        };
        CertificateMonitor monitor = new CertificateMonitor(
                failFirst, CHECK_INTERVAL, WARN_BEFORE);
        monitor.register(bad, "a");
        monitor.register(good, "b");

        // No exception propagated; both certs were attempted.
        monitor.check();
    }

    @Test
    void registerBundleAddsChainCertificates() throws Exception {
        KeyPair rootKeys = PkiKeys.rsa(2048);
        X509Certificate root = PkiCertificate.selfSigned()
                .subject("CN=bundle-root").keyPair(rootKeys)
                .validFor(Duration.ofDays(3650)).isCA(true).build();

        io.github.kaplaukhd.easypki.Pkcs12Bundle bundle = io.github.kaplaukhd.easypki.PkiPkcs12
                .create()
                .certificate(root).alias("root").password("x").build();

        CertificateMonitor monitor = new CertificateMonitor(
                new RecordingPublisher(), CHECK_INTERVAL, WARN_BEFORE);
        monitor.registerBundle(bundle, "truststore");

        assertThat(monitor.monitored()).hasSize(1);
        assertThat(monitor.monitored().get(0).getEncoded()).isEqualTo(root.getEncoded());
    }

    // ---------- test helpers ----------

    private static X509Certificate newCert(Duration validFor) {
        KeyPair keys = PkiKeys.rsa(2048);
        return PkiCertificate.selfSigned()
                .subject("CN=monitor-" + System.nanoTime())
                .keyPair(keys)
                .validFor(validFor)
                .build();
    }

    /** Collects published events for assertion without a Spring context. */
    private static final class RecordingPublisher implements ApplicationEventPublisher {
        final List<CertExpiringEvent> expiring = new ArrayList<>();
        final List<CertExpiredEvent> expired = new ArrayList<>();

        @Override
        public void publishEvent(Object event) {
            if (event instanceof CertExpiringEvent e) {
                expiring.add(e);
            } else if (event instanceof CertExpiredEvent e) {
                expired.add(e);
            }
        }
    }
}
