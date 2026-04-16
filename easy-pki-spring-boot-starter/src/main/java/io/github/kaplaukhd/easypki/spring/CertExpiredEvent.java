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
import java.time.Instant;

import org.springframework.context.ApplicationEvent;

/**
 * Published by {@link CertificateMonitor} when a monitored certificate has
 * already expired (its {@code notAfter} is in the past).
 */
public class CertExpiredEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    private final X509Certificate certificate;
    private final String alias;

    public CertExpiredEvent(CertificateMonitor source,
                            X509Certificate certificate,
                            String alias) {
        super(source);
        this.certificate = certificate;
        this.alias = alias;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getAlias() {
        return alias;
    }

    public Instant getNotAfter() {
        return certificate.getNotAfter().toInstant();
    }
}
