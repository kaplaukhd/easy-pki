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

import org.springframework.context.ApplicationEvent;

/**
 * Published by {@link CertificateMonitor} when a monitored certificate is
 * still valid but its {@code notAfter} is within the configured
 * {@code easy-pki.monitoring.warn-before} window.
 *
 * <p>The event source is the {@link CertificateMonitor} instance.
 */
public class CertExpiringEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    private final X509Certificate certificate;
    private final String alias;
    private final Duration timeLeft;

    public CertExpiringEvent(CertificateMonitor source,
                             X509Certificate certificate,
                             String alias,
                             Duration timeLeft) {
        super(source);
        this.certificate = certificate;
        this.alias = alias;
        this.timeLeft = timeLeft;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    /** Short, human-readable identifier for the certificate's source (keystore alias, etc.). */
    public String getAlias() {
        return alias;
    }

    /** Remaining validity at the time the event was published. */
    public Duration getTimeLeft() {
        return timeLeft;
    }

    /** Convenience: remaining validity rounded to whole days. */
    public long getDaysLeft() {
        return timeLeft.toDays();
    }

    /** The {@code notAfter} instant of the certificate. */
    public Instant getNotAfter() {
        return certificate.getNotAfter().toInstant();
    }
}
