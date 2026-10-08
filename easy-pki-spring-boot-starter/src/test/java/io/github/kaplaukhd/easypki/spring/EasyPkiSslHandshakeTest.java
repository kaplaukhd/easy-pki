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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.TrustBundle;
import io.github.kaplaukhd.easypki.tls.PkiTls;
import io.github.kaplaukhd.easypki.tls.ReloadableTlsContext;
import io.github.kaplaukhd.easypki.tls.TlsPeerPolicy;
import io.github.kaplaukhd.easypki.validation.PkiCrl;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.List;
import java.util.function.Consumer;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SNIHostName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslBundleRegistrar;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

class EasyPkiSslHandshakeTest {
    private static final KeyPair CA_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate CA = PkiCertificate.rootCa().subject("CN=Handshake CA")
            .keyPair(CA_KEYS).validFor(Duration.ofDays(365)).build();
    private static final PkiIdentity CA_IDENTITY = PkiIdentity.of(CA, CA_KEYS.getPrivate());
    private static final PkiIdentity SERVER = identity(true, "localhost", true, CA_IDENTITY);
    private static final PkiIdentity CLIENT = identity(false, "Client One", false, CA_IDENTITY);
    private static final TrustBundle TRUST = TrustBundle.of(CA);

    @Test
    void namedBundlesWorkWithRealTomcatAndSpringRestClient() {
        ReloadableTlsContext server = material(SERVER, TRUST);
        ReloadableTlsContext client = material(CLIENT, TRUST);
        try (var application = start(server)) {
            withClient(client, rest -> assertThat(get(rest, application)).isEqualTo(CLIENT.getCertificate().getSerialNumber().toString()));
        }
    }

    @Test
    void absentClientIdentityAndUntrustedClientAreRejectedByTomcat() {
        KeyPair otherKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate otherCa = PkiCertificate.rootCa().subject("CN=Untrusted CA").keyPair(otherKeys)
                .validFor(Duration.ofDays(365)).build();
        PkiIdentity foreignClient = identity(false, "Foreign Client", false, PkiIdentity.of(otherCa, otherKeys.getPrivate()));
        try (var application = start(material(SERVER, TRUST))) {
            withClient(material(null, TRUST), rest -> assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class));
            withClient(material(foreignClient, TRUST), rest -> assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class));
        }
    }

    @Test
    void clientDoesNotUsePlatformRootsWhenExplicitTrustIsEmpty() {
        try (var application = start(material(SERVER, TRUST))) {
            withClient(material(CLIENT, TrustBundle.of()), rest ->
                    assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class));
        }
    }

    @Test
    void serverNamesRequireMatchingSanWithoutCommonNameFallback() {
        PkiIdentity wrongName = identity(true, "wrong.example", true, CA_IDENTITY);
        PkiIdentity commonNameOnly = identity(true, "127.0.0.1", false, CA_IDENTITY);
        for (PkiIdentity server : new PkiIdentity[]{wrongName, commonNameOnly}) {
            try (var application = start(material(server, TRUST))) {
                withClient(material(CLIENT, TRUST), rest ->
                        assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class));
            }
        }
    }

    @Test
    void revokedClientProvesTomcatUsesTheCustomPeerPolicy() {
        var crl = PkiCrl.issued().issuer(CA, CA_KEYS.getPrivate())
                .thisUpdate(Instant.now().minusSeconds(60)).nextUpdate(Duration.ofHours(1))
                .revoke(CLIENT.getCertificate(), RevocationReason.KEY_COMPROMISE).build();
        ReloadableTlsContext server = PkiTls.builder().identity(SERVER).trust(TRUST)
                .peerPolicy(TlsPeerPolicy.withCrls(crl)).build();
        try (var application = start(server)) {
            withClient(material(CLIENT, TRUST), rest ->
                    assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class));
            PkiIdentity allowed = identity(false, "Other Client", false, CA_IDENTITY);
            withClient(material(allowed, TRUST), rest -> assertThat(get(rest, application))
                    .isEqualTo(allowed.getCertificate().getSerialNumber().toString()));
        }
    }

    @Test
    void existingBundleAndServerUseNewIdentityForFreshHandshakes() throws Exception {
        ReloadableTlsContext server = material(SERVER, TRUST);
        ReloadableTlsContext client = material(CLIENT, TRUST);
        PkiIdentity replacementServer = identity(true, "localhost", true, CA_IDENTITY);
        PkiIdentity replacementClient = identity(false, "Client Two", false, CA_IDENTITY);
        try (var application = start(server)) {
            assertThat(peerSerial(client, application)).isEqualTo(SERVER.getCertificate().getSerialNumber());
            server.reloadIdentity(replacementServer);
            assertThat(peerSerial(client, application)).isEqualTo(replacementServer.getCertificate().getSerialNumber());
            withClient(client, rest -> {
                assertThat(get(rest, application)).isEqualTo(CLIENT.getCertificate().getSerialNumber().toString());
                client.reloadIdentity(replacementClient);
                assertThat(get(rest, application)).isEqualTo(replacementClient.getCertificate().getSerialNumber().toString());
            });
        }
    }

    @Test
    void sameServerAndClientHonorTrustRemovalAndRestoration() {
        ReloadableTlsContext server = material(SERVER, TRUST);
        ReloadableTlsContext client = material(CLIENT, TRUST);
        try (var application = start(server)) {
            withClient(client, rest -> {
                assertThat(get(rest, application)).isEqualTo(CLIENT.getCertificate().getSerialNumber().toString());
                server.reloadTrust(TrustBundle.of());
                assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class);
                server.reloadTrust(TRUST);
                assertThat(get(rest, application)).isEqualTo(CLIENT.getCertificate().getSerialNumber().toString());
                client.reloadTrust(TrustBundle.of());
                assertThatThrownBy(() -> get(rest, application)).isInstanceOf(ResourceAccessException.class);
                client.reloadTrust(TRUST);
                assertThat(get(rest, application)).isEqualTo(CLIENT.getCertificate().getSerialNumber().toString());
            });
        }
    }

    @Test
    void namedSniHostUsesItsLiveContextAfterTomcatNormalizesTheName() throws Exception {
        PkiIdentity alternative = identity(true, "service.example.test", true, CA_IDENTITY);
        PkiIdentity replacement = identity(true, "service.example.test", true, CA_IDENTITY);
        ReloadableTlsContext alternateMaterial = material(alternative, TRUST);
        ReloadableTlsContext client = material(CLIENT, TRUST);
        try (var application = start(material(SERVER, TRUST), context -> {
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("sni", Map.of(
                    "server.ssl.server-name-bundles[0].server-name", "SERVICE.EXAMPLE.TEST",
                    "server.ssl.server-name-bundles[0].bundle", "alternate")));
            context.registerBean("alternateRegistrar", SslBundleRegistrar.class,
                    () -> registry -> registry.registerBundle("alternate", EasyPkiSslBundle.of(alternateMaterial)));
        })) {
            assertThat(sniPeerSerial(client, application)).isEqualTo(alternative.getCertificate().getSerialNumber());
            alternateMaterial.reloadIdentity(replacement);
            assertThat(sniPeerSerial(client, application)).isEqualTo(replacement.getCertificate().getSerialNumber());
        }
    }

    private static PkiIdentity identity(boolean server, String name, boolean san, PkiIdentity issuer) {
        KeyPair keys = PkiKeys.ec(Curve.P_256);
        var builder = PkiCertificate.signed().subject("CN=" + name).keyPair(keys).issuer(issuer)
                .validFor(Duration.ofDays(30)).keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(server ? ExtendedKeyUsage.TLS_SERVER : ExtendedKeyUsage.TLS_CLIENT);
        if (san) builder.san(s -> {
            s.dns(name);
            if ("localhost".equals(name)) s.ip("127.0.0.1");
        });
        return PkiIdentity.of(builder.build(), keys.getPrivate(), issuer.getCertificate());
    }

    private static ReloadableTlsContext material(PkiIdentity identity, TrustBundle trust) {
        var builder = PkiTls.builder().trust(trust).peerPolicy(TlsPeerPolicy.withoutRevocationChecks());
        if (identity != null) builder.identity(identity);
        return builder.build();
    }

    private static AnnotationConfigServletWebServerApplicationContext start(ReloadableTlsContext material) {
        return start(material, context -> {});
    }

    private static AnnotationConfigServletWebServerApplicationContext start(ReloadableTlsContext material,
            Consumer<AnnotationConfigServletWebServerApplicationContext> configure) {
        var context = new AnnotationConfigServletWebServerApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("tls", Map.of(
                "easy-pki.ssl.bundle-name", "server", "server.ssl.bundle", "server",
                "server.ssl.client-auth", "need", "server.port", "0", "server.address", "127.0.0.1")));
        context.registerBean("serverTls", ReloadableTlsContext.class, () -> material);
        context.register(ServerApplication.class);
        configure.accept(context);
        try {
            context.refresh();
            return context;
        } catch (RuntimeException | Error failure) {
            context.close();
            throw failure;
        }
    }

    private static void withClient(ReloadableTlsContext material, Consumer<RestClient> action) {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(EasyPkiAutoConfiguration.class,
                        EasyPkiSslAutoConfiguration.class, SslAutoConfiguration.class,
                        HttpMessageConvertersAutoConfiguration.class, RestClientAutoConfiguration.class))
                .withBean(ReloadableTlsContext.class, () -> material)
                .withPropertyValues("easy-pki.ssl.bundle-name=client").run(context -> {
                    assertThat(context).hasNotFailed();
                    RestClient client = context.getBean(RestClient.Builder.class)
                            .apply(context.getBean(RestClientSsl.class).fromBundle("client")).build();
                    action.accept(client);
                });
    }

    private static String get(RestClient client, AnnotationConfigServletWebServerApplicationContext application) {
        return client.get().uri("https://127.0.0.1:" + application.getWebServer().getPort() + "/")
                .retrieve().body(String.class);
    }

    private static BigInteger peerSerial(ReloadableTlsContext client,
            AnnotationConfigServletWebServerApplicationContext application) throws Exception {
        try (SSLSocket socket = (SSLSocket) client.getSslContext().getSocketFactory()
                .createSocket("127.0.0.1", application.getWebServer().getPort())) {
            socket.setSoTimeout(5000);
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            return ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSerialNumber();
        }
    }

    private static BigInteger sniPeerSerial(ReloadableTlsContext client,
            AnnotationConfigServletWebServerApplicationContext application) throws Exception {
        int port = application.getWebServer().getPort();
        try (Socket plain = new Socket("127.0.0.1", port);
                SSLSocket socket = (SSLSocket) client.getSslContext().getSocketFactory()
                        .createSocket(plain, "service.example.test", port, true)) {
            socket.setSoTimeout(5000);
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            parameters.setServerNames(List.of(new SNIHostName("service.example.test")));
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            return ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSerialNumber();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration({EasyPkiAutoConfiguration.class, EasyPkiSslAutoConfiguration.class,
            SslAutoConfiguration.class, ServletWebServerFactoryAutoConfiguration.class})
    static class ServerApplication {
        @Bean ServletRegistrationBean<HttpServlet> applicationServlet() {
            return new ServletRegistrationBean<>(new PeerServlet(), "/");
        }
    }

    private static final class PeerServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;
        @Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            X509Certificate[] chain = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
            response.setHeader("Connection", "close");
            response.setContentType("text/plain");
            response.getWriter().write(chain[0].getSerialNumber().toString());
        }
    }
}
