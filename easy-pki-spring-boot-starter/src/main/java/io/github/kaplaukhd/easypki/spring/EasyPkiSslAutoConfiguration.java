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

import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.TrustBundle;
import io.github.kaplaukhd.easypki.tls.PkiTls;
import io.github.kaplaukhd.easypki.tls.ReloadableTlsContext;
import io.github.kaplaukhd.easypki.tls.TlsPeerPolicy;
import java.util.Optional;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslBundleRegistrar;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * Opt-in named SSL bundle integration. Existing easy-pki store/validator properties
 * do not enable TLS. A user-owned SSL registry suppresses automatic registration.
 */
@AutoConfiguration(after = EasyPkiAutoConfiguration.class, before = SslAutoConfiguration.class)
@ConditionalOnClass(SslBundle.class)
public class EasyPkiSslAutoConfiguration {
    /** Name of the default store-derived TLS context bean. */
    public static final String TLS_CONTEXT_BEAN = "easyPkiTlsContext";
    /** Name of the default Spring SSL bundle adapter bean. */
    public static final String SSL_BUNDLE_BEAN = "easyPkiSslBundle";
    /** Name of the registrar, allowing applications to replace registration. */
    public static final String SSL_REGISTRAR_BEAN = "easyPkiSslBundleRegistrar";

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "easy-pki.ssl", name = "bundle-name")
    @ConditionalOnMissingBean({SslBundles.class, SslBundleRegistry.class})
    @EnableConfigurationProperties(EasyPkiSslProperties.class)
    static class BundleRegistration {
        @Bean(TLS_CONTEXT_BEAN)
        @ConditionalOnMissingBean({ReloadableTlsContext.class, EasyPkiSslBundle.class})
        ReloadableTlsContext easyPkiTlsContext(EasyPkiSslProperties properties,
                ObjectProvider<TlsPeerPolicy> peerPolicies,
                @Qualifier(EasyPkiAutoConfiguration.KEY_STORE_BEAN) Optional<Pkcs12Bundle> keyStore,
                @Qualifier(EasyPkiAutoConfiguration.TRUST_STORE_BEAN) Optional<Pkcs12Bundle> trustStore) {
            Pkcs12Bundle trusted = trustStore.orElseThrow(() -> new IllegalStateException(
                    "SSL bundle requires an explicit easyPkiTrustStore or an application ReloadableTlsContext"));
            if (trusted.getPrivateKey() != null) {
                throw new IllegalArgumentException("SSL trust store must contain explicit trusted certificates, not an identity chain");
            }
            TlsPeerPolicy policy = peerPolicies.getIfAvailable();
            if (policy != null && properties.revocationMode() != null) {
                throw new IllegalStateException("Choose a TlsPeerPolicy bean or easy-pki.ssl.revocation-mode, not both");
            }
            if (policy == null) {
                if (properties.revocationMode() != EasyPkiSslProperties.RevocationMode.DISABLED) {
                    throw new IllegalStateException("SSL requires an explicit TlsPeerPolicy bean or easy-pki.ssl.revocation-mode=disabled");
                }
                policy = TlsPeerPolicy.withoutRevocationChecks();
            }
            var builder = PkiTls.builder().trust(TrustBundle.of(trusted.getChain())).peerPolicy(policy);
            keyStore.ifPresent(bundle -> builder.identity(PkiIdentity.fromPkcs12(bundle)));
            return builder.build();
        }

        @Bean(SSL_BUNDLE_BEAN)
        @ConditionalOnMissingBean(EasyPkiSslBundle.class)
        EasyPkiSslBundle easyPkiSslBundle(ReloadableTlsContext context) {
            return EasyPkiSslBundle.of(context);
        }

        @Bean(SSL_REGISTRAR_BEAN)
        @ConditionalOnMissingBean(name = SSL_REGISTRAR_BEAN)
        SslBundleRegistrar easyPkiSslBundleRegistrar(EasyPkiSslProperties properties, EasyPkiSslBundle bundle) {
            if (!StringUtils.hasText(properties.bundleName())) {
                throw new IllegalArgumentException("easy-pki.ssl.bundle-name must not be blank");
            }
            return registry -> registry.registerBundle(properties.bundleName(), bundle);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.apache.coyote.http11.AbstractHttp11JsseProtocol")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class TomcatConfiguration {
        @Bean
        WebServerFactoryCustomizer<TomcatServletWebServerFactory> easyPkiTomcatSslCustomizer() {
            return new EasyPkiTomcatSslCustomizer();
        }
    }
}
