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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import io.github.kaplaukhd.easypki.PkiCertInfo;
import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

/**
 * Spring Boot Actuator health indicator for easy-pki.
 *
 * <p>Status:
 * <ul>
 *   <li>{@code DOWN} if any certificate in the trust or key store has
 *       already expired.</li>
 *   <li>{@code UP} otherwise. Certificates expiring within the configured
 *       warn window are still {@code UP} but flagged in the details.</li>
 * </ul>
 *
 * <p>Details include, per configured store, every chain entry with subject
 * DN, {@code notAfter}, remaining days, and a status marker ({@code OK} /
 * {@code EXPIRING} / {@code EXPIRED}).
 */
public final class EasyPkiHealthIndicator implements HealthIndicator {

    private final Optional<Pkcs12Bundle> trustStore;
    private final Optional<Pkcs12Bundle> keyStore;
    private final Duration warnBefore;

    public EasyPkiHealthIndicator(Optional<Pkcs12Bundle> trustStore,
                                  Optional<Pkcs12Bundle> keyStore,
                                  Duration warnBefore) {
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.warnBefore = Objects.requireNonNull(warnBefore, "warnBefore");
    }

    @Override
    public Health health() {
        Map<String, Object> details = new LinkedHashMap<>();
        boolean anyExpired = false;

        anyExpired |= describe(trustStore, EasyPkiAutoConfiguration.TRUST_STORE_BEAN, details);
        anyExpired |= describe(keyStore, EasyPkiAutoConfiguration.KEY_STORE_BEAN, details);

        Health.Builder builder = anyExpired ? Health.down() : Health.up();
        details.forEach(builder::withDetail);
        return builder.build();
    }

    /** Populates {@code details} for a bundle; returns {@code true} if any cert has expired. */
    private boolean describe(Optional<Pkcs12Bundle> bundle,
                             String baseAlias,
                             Map<String, Object> details) {
        if (bundle.isEmpty()) {
            return false;
        }
        Instant now = Instant.now();
        boolean anyExpired = false;
        List<X509Certificate> chain = bundle.get().getChain();
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            PkiCertInfo info = PkiCertInfo.of(cert);
            Map<String, Object> certDetails = new LinkedHashMap<>();
            certDetails.put("subject", info.getSubject());
            certDetails.put("notAfter", info.getNotAfter().toString());

            if (info.isExpired()) {
                certDetails.put("status", "EXPIRED");
                anyExpired = true;
            } else if (info.isExpiringWithin(warnBefore)) {
                certDetails.put("status", "EXPIRING");
                certDetails.put("daysLeft",
                        Duration.between(now, info.getNotAfter()).toDays());
            } else {
                certDetails.put("status", "OK");
                certDetails.put("daysLeft",
                        Duration.between(now, info.getNotAfter()).toDays());
            }

            details.put(baseAlias + "[" + i + "]", certDetails);
        }
        return anyExpired;
    }
}
