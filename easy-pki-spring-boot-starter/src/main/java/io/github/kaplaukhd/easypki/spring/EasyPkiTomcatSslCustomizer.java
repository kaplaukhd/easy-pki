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

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.core.Ordered;
import org.springframework.util.StringUtils;

/** Installs the live policy-aware context after Boot's store-based Tomcat configuration. */
final class EasyPkiTomcatSslCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory>, Ordered {
    private static final String JSSE = "org.apache.tomcat.util.net.jsse.JSSEImplementation";

    @Override public int getOrder() { return Ordered.LOWEST_PRECEDENCE; }

    @Override public void customize(TomcatServletWebServerFactory factory) {
        Ssl ssl = factory.getSsl();
        SslBundles registry = factory.getSslBundles();
        if (!Ssl.isEnabled(ssl) || registry == null) return;
        Map<String, EasyPkiSslBundle> bundles = new LinkedHashMap<>();
        addBundle(bundles, null, ssl.getBundle(), registry);
        for (Ssl.ServerNameSslBundle named : ssl.getServerNameBundles()) {
            addBundle(bundles, named.serverName(), named.bundle(), registry);
        }
        if (bundles.isEmpty()) return;
        factory.addConnectorCustomizers(connector -> {
            if (!(connector.getProtocolHandler() instanceof AbstractHttp11JsseProtocol<?> protocol)) {
                throw new IllegalStateException("easy-pki SSL bundles require a JSSE Tomcat connector");
            }
            String implementation = protocol.getSslImplementationName();
            if (implementation != null && !JSSE.equals(implementation)) {
                throw new IllegalStateException("easy-pki SSL bundles support Tomcat JSSE, not " + implementation);
            }
            protocol.setSslImplementationName(JSSE);
            for (SSLHostConfig host : protocol.findSslHostConfigs()) {
                String name = host.getHostName().equals(protocol.getDefaultSSLHostConfigName()) ? null : host.getHostName();
                EasyPkiSslBundle bundle = bundles.get(name);
                if (bundle == null) continue;
                if (bundle.snapshot().getIdentity().isEmpty()) {
                    throw new IllegalStateException("A Tomcat server SSL bundle requires a TLS identity");
                }
                host.getCertificates(true).forEach(certificate -> certificate.setSslContext(new TomcatContext(bundle)));
            }
        });
    }

    private static void addBundle(Map<String, EasyPkiSslBundle> bundles, String host, String name, SslBundles registry) {
        if (StringUtils.hasText(name) && registry.getBundle(name) instanceof EasyPkiSslBundle bundle) {
            bundles.put(host != null ? host.toLowerCase(Locale.ROOT) : null, bundle);
        }
    }

    private static final class TomcatContext implements org.apache.tomcat.util.net.SSLContext {
        private final EasyPkiSslBundle bundle;
        private TomcatContext(EasyPkiSslBundle bundle) { this.bundle = bundle; }
        @Override public void init(KeyManager[] keys, TrustManager[] trust, SecureRandom random) throws KeyManagementException {
            throw new KeyManagementException("The easy-pki TLS context is already initialized");
        }
        @Override public void destroy() { /* The application owns the TLS context. */ }
        @Override public SSLSessionContext getServerSessionContext() { return bundle.createSslContext().getServerSessionContext(); }
        @Override public SSLEngine createSSLEngine() { return bundle.createSslContext().createSSLEngine(); }
        @Override public SSLServerSocketFactory getServerSocketFactory() { return bundle.createSslContext().getServerSocketFactory(); }
        @Override public SSLParameters getSupportedSSLParameters() { return bundle.createSslContext().getSupportedSSLParameters(); }
        @Override public X509Certificate[] getCertificateChain(String alias) {
            return bundle.snapshot().getIdentity().map(identity -> identity.getChain().toArray(X509Certificate[]::new)).orElse(null);
        }
        @Override public X509Certificate[] getAcceptedIssuers() {
            return bundle.snapshot().getTrustBundle().getTrustAnchors().toArray(X509Certificate[]::new);
        }
    }
}
