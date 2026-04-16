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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.List;

import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

/**
 * Spring Boot auto-configuration for easy-pki.
 *
 * <ul>
 *   <li>Binds {@link EasyPkiProperties} from the {@code easy-pki.*} namespace.</li>
 *   <li>Loads a PKCS#12 trust store when {@code easy-pki.trust-store.path} is set,
 *       exposing it as a {@link Pkcs12Bundle} bean qualified
 *       {@value #TRUST_STORE_BEAN}.</li>
 *   <li>Loads a PKCS#12 key store when {@code easy-pki.key-store.path} is set,
 *       exposing it as a {@link Pkcs12Bundle} bean qualified
 *       {@value #KEY_STORE_BEAN}.</li>
 *   <li>Exposes an {@link EasyPkiValidator} pre-configured with trust anchors
 *       from the trust store and the revocation mode from
 *       {@code easy-pki.validation.mode}.</li>
 * </ul>
 *
 * <p>All beans are conditional on the corresponding property being present and
 * on the user not having defined their own bean with the same qualifier.
 */
@AutoConfiguration
@EnableConfigurationProperties(EasyPkiProperties.class)
public class EasyPkiAutoConfiguration {

    /** Qualifier for the auto-loaded trust store {@link Pkcs12Bundle} bean. */
    public static final String TRUST_STORE_BEAN = "easyPkiTrustStore";

    /** Qualifier for the auto-loaded key store {@link Pkcs12Bundle} bean. */
    public static final String KEY_STORE_BEAN = "easyPkiKeyStore";

    @Bean(TRUST_STORE_BEAN)
    @Qualifier(TRUST_STORE_BEAN)
    @ConditionalOnProperty(prefix = "easy-pki.trust-store", name = "path")
    @ConditionalOnMissingBean(name = TRUST_STORE_BEAN)
    public Pkcs12Bundle easyPkiTrustStore(EasyPkiProperties properties) {
        return loadBundle(properties.trustStore(), "trust-store");
    }

    @Bean(KEY_STORE_BEAN)
    @Qualifier(KEY_STORE_BEAN)
    @ConditionalOnProperty(prefix = "easy-pki.key-store", name = "path")
    @ConditionalOnMissingBean(name = KEY_STORE_BEAN)
    public Pkcs12Bundle easyPkiKeyStore(EasyPkiProperties properties) {
        return loadBundle(properties.keyStore(), "key-store");
    }

    @Bean
    @ConditionalOnMissingBean
    public EasyPkiValidator easyPkiValidator(EasyPkiProperties properties,
                                             @Qualifier(TRUST_STORE_BEAN)
                                             java.util.Optional<Pkcs12Bundle> trustStore) {
        EasyPkiProperties.Validation v = properties.validation();
        List<java.security.cert.X509Certificate> anchors = trustStore
                .map(Pkcs12Bundle::getChain)
                .orElse(Collections.emptyList());
        return new EasyPkiValidator(
                anchors,
                v.mode(),
                v.ocspTimeout(),
                v.crlCacheTtl(),
                v.httpTimeout(),
                v.proxy());
    }

    /**
     * Periodic certificate-expiry monitor. Created only when
     * {@code easy-pki.monitoring.enabled=true}. The trust-store and key-store
     * chains (when present) are auto-registered for monitoring.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "easy-pki.monitoring", name = "enabled", havingValue = "true")
    public CertificateMonitor easyPkiCertificateMonitor(
            EasyPkiProperties properties,
            ApplicationEventPublisher publisher,
            @Qualifier(TRUST_STORE_BEAN) java.util.Optional<Pkcs12Bundle> trustStore,
            @Qualifier(KEY_STORE_BEAN) java.util.Optional<Pkcs12Bundle> keyStore) {

        EasyPkiProperties.Monitoring m = properties.monitoring();
        CertificateMonitor monitor = new CertificateMonitor(
                publisher, m.checkInterval(), m.warnBefore());
        trustStore.ifPresent(b -> monitor.registerBundle(b, TRUST_STORE_BEAN));
        keyStore.ifPresent(b -> monitor.registerBundle(b, KEY_STORE_BEAN));
        return monitor;
    }

    /**
     * Registers an Actuator {@code HealthIndicator} exposing the current
     * status of the easy-pki trust / key stores. Activated only when
     * Spring Boot Actuator is on the classpath.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
    public static class ActuatorConfiguration {

        /** Qualifier for the auto-registered {@link EasyPkiHealthIndicator} bean. */
        public static final String HEALTH_BEAN = "easyPkiHealthIndicator";

        @Bean(HEALTH_BEAN)
        @ConditionalOnMissingBean(name = HEALTH_BEAN)
        public EasyPkiHealthIndicator easyPkiHealthIndicator(
                EasyPkiProperties properties,
                @Qualifier(TRUST_STORE_BEAN) java.util.Optional<Pkcs12Bundle> trustStore,
                @Qualifier(KEY_STORE_BEAN) java.util.Optional<Pkcs12Bundle> keyStore) {
            return new EasyPkiHealthIndicator(
                    trustStore, keyStore, properties.monitoring().warnBefore());
        }
    }

    private static Pkcs12Bundle loadBundle(EasyPkiProperties.Store store, String name) {
        if (store == null) {
            throw new IllegalStateException(
                    "easy-pki." + name + ".path is set but the store definition is empty");
        }
        Resource path = store.path();
        if (path == null) {
            throw new IllegalStateException(
                    "easy-pki." + name + ".path is required to load the " + name);
        }
        if (!"PKCS12".equalsIgnoreCase(store.type())) {
            throw new IllegalStateException(
                    "Only PKCS12 stores are supported, got " + store.type()
                            + " for easy-pki." + name);
        }
        String password = store.password() != null ? store.password() : "";
        try (InputStream in = path.getInputStream()) {
            return PkiPkcs12.load(in.readAllBytes(), password);
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Failed to read easy-pki." + name + " from " + path, e);
        }
    }
}
