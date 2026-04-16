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

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;

/**
 * Binding for {@code easy-pki.*} configuration.
 *
 * <pre>{@code
 * easy-pki:
 *   trust-store:
 *     path: classpath:truststore.p12
 *     password: changeit
 *     type: PKCS12
 *   key-store:
 *     path: /etc/ssl/keystore.p12
 *     password: ${KEYSTORE_PASSWORD}
 *   validation:
 *     mode: OCSP_WITH_CRL_FALLBACK
 *     ocsp-timeout: 5s
 *     crl-cache-ttl: 30m
 *     proxy: http://proxy.corp:3128
 *   monitoring:
 *     enabled: true
 *     warn-before: 30d
 *     check-interval: 12h
 * }</pre>
 */
@ConfigurationProperties(prefix = "easy-pki")
public record EasyPkiProperties(
        Store trustStore,
        Store keyStore,
        @DefaultValue Validation validation,
        @DefaultValue Monitoring monitoring) {

    /** Location and password of a PKCS#12 keystore. */
    public record Store(Resource path, String password, @DefaultValue("PKCS12") String type) {
    }

    /** Revocation-checking parameters. */
    public record Validation(
            @DefaultValue("OCSP_WITH_CRL_FALLBACK") ValidationMode mode,
            @DefaultValue("5s") Duration ocspTimeout,
            @DefaultValue("30m") Duration crlCacheTtl,
            @DefaultValue("10s") Duration httpTimeout,
            String proxy) {
    }

    /** Scheduled expiry-monitor parameters (used by the monitoring module). */
    public record Monitoring(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("30d") Duration warnBefore,
            @DefaultValue("12h") Duration checkInterval) {
    }
}
