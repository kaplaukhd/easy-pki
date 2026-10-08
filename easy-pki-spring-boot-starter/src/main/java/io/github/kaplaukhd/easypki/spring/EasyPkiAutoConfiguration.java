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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import io.github.kaplaukhd.easypki.TrustBundle;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionReaderUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ResolvableType;
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

    /**
     * Loads every trusted X.509 certificate entry, in alias order. This
     * qualified trust-store bundle exposes the flat anchor list through
     * {@link Pkcs12Bundle#getChain()}; its primary certificate and alias are
     * the first trusted entry, and it contains no private key. Private-key
     * entries and their chains do not establish trust.
     */
    @Bean(TRUST_STORE_BEAN)
    @Qualifier(TRUST_STORE_BEAN)
    @ConditionalOnProperty(prefix = "easy-pki.trust-store", name = "path")
    @ConditionalOnMissingBean(name = TRUST_STORE_BEAN)
    public Pkcs12Bundle easyPkiTrustStore(EasyPkiProperties properties) {
        return loadTrustBundle(properties.trustStore());
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

    /**
     * Exposes the {@link EasyPkiClientCertFilter} when the Servlet API and
     * Spring Web are on the classpath. Servlet registration is disabled by
     * default, so applications opt in by adding the bean to their
     * {@code SecurityFilterChain} (typically before
     * {@code X509AuthenticationFilter}), or by overriding the named servlet
     * registration bean.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {
            "jakarta.servlet.Filter",
            "org.springframework.web.filter.OncePerRequestFilter"
    })
    public static class SecurityConfiguration {

        /** Qualifier for the auto-registered {@link EasyPkiClientCertFilter} bean. */
        public static final String FILTER_BEAN = "easyPkiClientCertFilter";

        /** Name of the disabled-by-default servlet registration bean. */
        public static final String FILTER_REGISTRATION_BEAN = "easyPkiClientCertFilterRegistration";

        @Bean(FILTER_BEAN)
        @ConditionalOnMissingBean(EasyPkiClientCertFilter.class)
        public EasyPkiClientCertFilter easyPkiClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, false);
        }

        /**
         * Declares disabled servlet registrations for all client-certificate
         * filter beans without instantiating them during post-processing.
         * Explicit application registrations remain effective. The default
         * filter (or a single custom filter) uses
         * {@value #FILTER_REGISTRATION_BEAN}, which the application may replace.
         */
        @Bean
        @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
        public static BeanFactoryPostProcessor easyPkiClientCertFilterRegistrations() {
            return beanFactory -> {
                if (!(beanFactory instanceof BeanDefinitionRegistry registry)) {
                    throw new IllegalStateException(
                            "Client-certificate filter registration requires a bean definition registry");
                }
                String[] filterNames = beanFactory.getBeanNamesForType(
                        EasyPkiClientCertFilter.class, true, false);
                Arrays.sort(filterNames);
                for (String filterName : filterNames) {
                    String registrationName;
                    if (filterNames.length == 1 || FILTER_BEAN.equals(filterName)) {
                        registrationName = FILTER_REGISTRATION_BEAN;
                        if (beanFactory.containsBean(registrationName)) {
                            continue;
                        }
                    } else {
                        registrationName = BeanDefinitionReaderUtils.uniqueBeanName(
                                filterName + ".easyPkiDisabledRegistration", registry);
                    }
                    RootBeanDefinition registration = new RootBeanDefinition(FilterRegistrationBean.class);
                    registration.setTargetType(ResolvableType.forClassWithGenerics(
                            FilterRegistrationBean.class, EasyPkiClientCertFilter.class));
                    registration.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
                    registration.getPropertyValues()
                            .add("filter", new RuntimeBeanReference(filterName))
                            .add("name", filterName)
                            .add("enabled", false);
                    registry.registerBeanDefinition(registrationName, registration);
                }
            };
        }
    }

    private static Pkcs12Bundle loadTrustBundle(EasyPkiProperties.Store store) {
        Resource path = storeResource(store, "trust-store");
        String password = store.password() != null ? store.password() : "";
        char[] passwordChars = password.toCharArray();
        try (InputStream in = path.getInputStream()) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, passwordChars);
            TrustBundle trustBundle = TrustBundle.fromKeyStore(keyStore);
            List<X509Certificate> anchors = trustBundle.getTrustAnchors();
            List<String> aliases = Collections.list(keyStore.aliases());
            Collections.sort(aliases);
            String firstAlias = null;
            for (String alias : aliases) {
                if (keyStore.isCertificateEntry(alias)) {
                    firstAlias = alias;
                    break;
                }
            }
            if (anchors.isEmpty()) {
                throw new IllegalArgumentException(
                        "PKCS#12 trust store contains no trusted X.509 certificate entries");
            }
            // Preserve the existing qualified bean type without using the
            // single-primary-entry loader or serialising this anchor snapshot.
            return PkiPkcs12.create()
                    .certificate(anchors.get(0))
                    .chain(anchors.subList(1, anchors.size()))
                    .alias(firstAlias)
                    .password(password)
                    .build();
        } catch (IOException e) {
            if (e.getCause() instanceof UnrecoverableKeyException) {
                throw new IllegalArgumentException("Wrong PKCS#12 password", e);
            }
            throw new UncheckedIOException(
                    "Failed to read easy-pki.trust-store from " + path, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to read PKCS#12 trust store", e);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    private static Pkcs12Bundle loadBundle(EasyPkiProperties.Store store, String name) {
        Resource path = storeResource(store, name);
        String password = store.password() != null ? store.password() : "";
        try (InputStream in = path.getInputStream()) {
            return PkiPkcs12.load(in.readAllBytes(), password);
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Failed to read easy-pki." + name + " from " + path, e);
        }
    }

    private static Resource storeResource(EasyPkiProperties.Store store, String name) {
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
        return path;
    }
}
