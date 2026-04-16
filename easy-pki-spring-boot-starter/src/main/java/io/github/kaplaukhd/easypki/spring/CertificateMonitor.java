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

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Periodically scans monitored certificates and publishes
 * {@link CertExpiringEvent} and {@link CertExpiredEvent}.
 *
 * <p>Managed by {@link EasyPkiAutoConfiguration} when
 * {@code easy-pki.monitoring.enabled=true}. Runs on its own
 * single-threaded {@link ScheduledExecutorService} so it does not depend on
 * {@code @EnableScheduling} in the host application.
 *
 * <p>The monitor scans, in addition to any certificates registered via
 * {@link #register(X509Certificate, String)}:
 * <ul>
 *   <li>Every certificate in the configured trust-store chain.</li>
 *   <li>Every certificate in the configured key-store chain.</li>
 * </ul>
 *
 * <p>To avoid repeated events, each certificate fires a given event type at
 * most once per run state — the monitor remembers which events have already
 * been dispatched and resets that state only across restarts.
 */
public final class CertificateMonitor {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateMonitor.class);

    private final ApplicationEventPublisher publisher;
    private final Duration checkInterval;
    private final Duration warnBefore;
    private final ConcurrentMap<String, X509Certificate> monitored = new ConcurrentHashMap<>();

    /**
     * Tracks which (alias → event type) pairs have already fired so monitors
     * running every 12 h don't spam the bus with duplicates. Keys are
     * {@code alias + "|" + eventType}.
     */
    private final ConcurrentMap<String, Boolean> fired = new ConcurrentHashMap<>();

    private ScheduledExecutorService scheduler;

    public CertificateMonitor(ApplicationEventPublisher publisher,
                              Duration checkInterval,
                              Duration warnBefore) {
        this.publisher = Objects.requireNonNull(publisher, "publisher");
        this.checkInterval = Objects.requireNonNull(checkInterval, "checkInterval");
        this.warnBefore = Objects.requireNonNull(warnBefore, "warnBefore");
    }

    /**
     * Adds a certificate for monitoring. A subsequent call with the same alias
     * replaces the previous entry.
     */
    public void register(X509Certificate certificate, String alias) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(alias, "alias");
        X509Certificate previous = monitored.put(alias, certificate);
        if (previous != null && !previous.equals(certificate)) {
            // Reset fire state for the alias — it's a different certificate now.
            fired.keySet().removeIf(k -> k.startsWith(alias + "|"));
        }
    }

    /** Adds every certificate in the given chain under aliases "{base}[{index}]". */
    public void registerAll(List<X509Certificate> chain, String baseAlias) {
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(baseAlias, "baseAlias");
        for (int i = 0; i < chain.size(); i++) {
            register(chain.get(i), baseAlias + "[" + i + "]");
        }
    }

    /** Adds every certificate from a PKCS#12 bundle under aliases "{base}[{index}]". */
    public void registerBundle(Pkcs12Bundle bundle, String baseAlias) {
        Objects.requireNonNull(bundle, "bundle");
        registerAll(bundle.getChain(), baseAlias);
    }

    /** Returns the current monitored set (immutable snapshot). */
    public List<X509Certificate> monitored() {
        return List.copyOf(monitored.values());
    }

    /** Runs a single expiry scan now. Safe to call from tests. */
    public void check() {
        Instant now = Instant.now();
        Instant warningHorizon = now.plus(warnBefore);

        for (var entry : monitored.entrySet()) {
            String alias = entry.getKey();
            X509Certificate cert = entry.getValue();
            Instant notAfter = cert.getNotAfter().toInstant();

            if (!now.isBefore(notAfter)) {
                publishOnce(alias, "expired", () ->
                        publisher.publishEvent(new CertExpiredEvent(this, cert, alias)));
                continue;
            }
            if (!warningHorizon.isBefore(notAfter)) {
                Duration left = Duration.between(now, notAfter);
                publishOnce(alias, "expiring", () ->
                        publisher.publishEvent(new CertExpiringEvent(this, cert, alias, left)));
            }
        }
    }

    private void publishOnce(String alias, String eventType, Runnable publish) {
        String key = alias + "|" + eventType;
        if (fired.putIfAbsent(key, Boolean.TRUE) == null) {
            try {
                publish.run();
            } catch (RuntimeException e) {
                // A failing listener should not break the whole run; log and continue.
                LOG.warn("Certificate-monitor listener failed for {} ({}): {}",
                        alias, eventType, e.getMessage());
                fired.remove(key);  // allow retry next run
            }
        }
    }

    /** Lifecycle — called once the bean is initialised. */
    @PostConstruct
    public void start() {
        if (scheduler != null) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "easy-pki-certificate-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(
                this::runSafely,
                0L,
                checkInterval.toMillis(),
                TimeUnit.MILLISECONDS);
        LOG.info("easy-pki certificate monitor started (interval={}, warnBefore={})",
                checkInterval, warnBefore);
    }

    private void runSafely() {
        try {
            check();
        } catch (RuntimeException e) {
            LOG.warn("easy-pki certificate monitor check failed: {}", e.getMessage());
        }
    }

    @PreDestroy
    public void stop() {
        ScheduledExecutorService s = this.scheduler;
        this.scheduler = null;
        if (s != null) {
            s.shutdownNow();
        }
    }
}
