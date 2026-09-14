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

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.RegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.MapPropertySource;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

class EasyPkiServletRegistrationTest {

    private static final String REGISTRATION_BEAN =
            EasyPkiAutoConfiguration.SecurityConfiguration.FILTER_REGISTRATION_BEAN;
    private static final KeyPair ROOT_KEYS = PkiKeys.rsa(2048);
    private static final X509Certificate ROOT = PkiCertificate.selfSigned()
            .subject("CN=Servlet Root").keyPair(ROOT_KEYS)
            .isCA(true).validFor(Duration.ofDays(365)).build();
    private static final X509Certificate CLIENT = PkiCertificate.signed()
            .subject("CN=Servlet Client").publicKey(PkiKeys.rsa(2048).getPublic())
            .issuer(ROOT, ROOT_KEYS.getPrivate()).validFor(Duration.ofDays(30)).build();

    @Test
    void defaultFilterBeanDoesNotRegisterWithTheServletContainer() throws Exception {
        try (var context = start()) {
            assertThat(context.getBean(EasyPkiClientCertFilter.class)).isNotNull();
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(context.getServletContext().getFilterRegistrations())
                    .doesNotContainKey("easyPkiClientCertFilter");
            assertThat(context.getBean(REGISTRATION_BEAN, RegistrationBean.class).isEnabled())
                    .isFalse();
        }
    }

    @Test
    void explicitServletRegistrationEnforcesClientCertificates() throws Exception {
        try (var context = start(ServletOptIn.class)) {
            assertThat(context.getServletContext().getFilterRegistrations())
                    .containsKey("easyPkiClientCertFilter");
            assertThat(status(context, "/protected/missing")).isEqualTo(401);
            assertThat(status(context, "/protected/trusted")).isEqualTo(204);
        }
    }

    @Test
    void explicitSecurityChainProtectsOnlyItsOwnPaths() throws Exception {
        try (var context = start(SecurityOptIn.class)) {
            assertThat(context.getServletContext().getFilterRegistrations())
                    .doesNotContainKey("easyPkiClientCertFilter");
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(status(context, "/protected/missing")).isEqualTo(401);
            assertThat(status(context, "/protected/trusted")).isEqualTo(204);
        }
    }

    @Test
    void customFilterBeanAlsoRemainsAvailableWithoutAutomaticRegistration() throws Exception {
        try (var context = start(CustomFilter.class)) {
            assertThat(context.getBeansOfType(EasyPkiClientCertFilter.class))
                    .containsOnlyKeys("customClientCertFilter");
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(context.getServletContext().getFilterRegistrations())
                    .doesNotContainKey("customClientCertFilter");
        }
    }

    @Test
    void multipleCustomFiltersWithExplicitDisabledRegistrationsStartNormally() throws Exception {
        try (var context = start(MultipleFilters.class, MultipleDisabledRegistrations.class)) {
            assertThat(context.getBeansOfType(EasyPkiClientCertFilter.class))
                    .containsOnlyKeys("firstClientCertFilter", "secondClientCertFilter");
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(context.getServletContext().getFilterRegistrations())
                    .doesNotContainKeys("firstClientCertFilter", "secondClientCertFilter");
        }
    }

    @Test
    void primaryFilterDoesNotLeaveAnotherCustomFilterAutomaticallyRegistered() throws Exception {
        try (var context = start(MultipleFiltersWithPrimary.class)) {
            assertThat(context.getBeansOfType(EasyPkiClientCertFilter.class))
                    .containsOnlyKeys("firstClientCertFilter", "secondClientCertFilter");
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(context.getServletContext().getFilterRegistrations())
                    .doesNotContainKeys("firstClientCertFilter", "secondClientCertFilter");
        }
    }

    @Test
    void explicitEnabledRegistrationForOneOfSeveralFiltersRemainsEffective() throws Exception {
        try (var context = start(MultipleFilters.class, SecondEnabledRegistration.class)) {
            assertThat(context.getServletContext().getFilterRegistrations())
                    .containsKey("explicitSecondFilter")
                    .doesNotContainKeys("firstClientCertFilter", "secondClientCertFilter");
            assertThat(status(context, "/public")).isEqualTo(204);
            assertThat(status(context, "/protected/missing")).isEqualTo(401);
            assertThat(status(context, "/protected/trusted")).isEqualTo(204);
        }
    }

    private static AnnotationConfigServletWebServerApplicationContext start(Class<?>... extra) {
        var context = new AnnotationConfigServletWebServerApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource(
                "test", Map.of("easy-pki.validation.mode", "NONE")));
        context.register(WebApplication.class);
        if (extra.length > 0) {
            context.register(extra);
        }
        context.register(EasyPkiAutoConfiguration.class);
        try {
            context.refresh();
            return context;
        } catch (RuntimeException | Error failure) {
            context.close();
            throw failure;
        }
    }

    private static int status(AnnotationConfigServletWebServerApplicationContext context,
                              String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(
                        "http://127.0.0.1:" + context.getWebServer().getPort() + path))
                .timeout(Duration.ofSeconds(10)).GET().build();
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Configuration(proxyBeanMethods = false)
    static class WebApplication {
        @Bean
        TomcatServletWebServerFactory webServerFactory() throws IOException {
            var factory = new TomcatServletWebServerFactory(0);
            factory.setAddress(InetAddress.getByName("127.0.0.1"));
            return factory;
        }

        @Bean
        EasyPkiValidator validator() {
            return new EasyPkiValidator(List.of(ROOT), ValidationMode.NONE,
                    Duration.ofSeconds(5), Duration.ofMinutes(30), Duration.ofSeconds(10), null);
        }

        @Bean
        ServletRegistrationBean<HttpServlet> applicationServlet() {
            return new ServletRegistrationBean<>(new StatusServlet(), "/");
        }

        @Bean
        FilterRegistrationBean<Filter> testCertificateSource() {
            // A trusted test fixture supplies the same servlet attribute a TLS connector sets.
            // HTTP clients cannot supply or modify this attribute themselves.
            Filter source = (request, response, chain) -> {
                if (((HttpServletRequest) request).getRequestURI().endsWith("/trusted")) {
                    request.setAttribute(EasyPkiClientCertFilter.CLIENT_CERT_ATTRIBUTE,
                            new X509Certificate[]{CLIENT, ROOT});
                }
                chain.doFilter(request, response);
            };
            var registration = new FilterRegistrationBean<>(source);
            registration.setOrder(-200);
            return registration;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ServletOptIn {
        @Bean(REGISTRATION_BEAN)
        FilterRegistrationBean<EasyPkiClientCertFilter> registration(EasyPkiClientCertFilter filter) {
            var registration = new FilterRegistrationBean<>(filter);
            registration.setName("easyPkiClientCertFilter");
            registration.setEnabled(true);
            return registration;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SecurityOptIn {
        @Bean
        SecurityFilterChain securityFilterChain(EasyPkiClientCertFilter filter) {
            return new DefaultSecurityFilterChain(new AntPathRequestMatcher("/protected/**"), filter);
        }

        @Bean
        FilterChainProxy springSecurityFilterChain(SecurityFilterChain chain) {
            return new FilterChainProxy(chain);
        }

        @Bean
        DelegatingFilterProxyRegistrationBean securityRegistration() {
            var registration = new DelegatingFilterProxyRegistrationBean("springSecurityFilterChain");
            registration.setOrder(-100);
            return registration;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomFilter {
        @Bean
        EasyPkiClientCertFilter customClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, true);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class MultipleFilters {
        @Bean
        EasyPkiClientCertFilter firstClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, true);
        }

        @Bean
        EasyPkiClientCertFilter secondClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, false);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class MultipleFiltersWithPrimary {
        @Bean
        @Primary
        EasyPkiClientCertFilter firstClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, true);
        }

        @Bean
        EasyPkiClientCertFilter secondClientCertFilter(EasyPkiValidator validator) {
            return new EasyPkiClientCertFilter(validator, false);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class MultipleDisabledRegistrations {
        @Bean
        FilterRegistrationBean<EasyPkiClientCertFilter> firstDisabledRegistration(
                @Qualifier("firstClientCertFilter") EasyPkiClientCertFilter filter) {
            var registration = new FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }

        @Bean
        FilterRegistrationBean<EasyPkiClientCertFilter> secondDisabledRegistration(
                @Qualifier("secondClientCertFilter") EasyPkiClientCertFilter filter) {
            var registration = new FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SecondEnabledRegistration {
        @Bean
        FilterRegistrationBean<EasyPkiClientCertFilter> applicationClientCertRegistration(
                @Qualifier("secondClientCertFilter") EasyPkiClientCertFilter filter) {
            var registration = new FilterRegistrationBean<>(filter);
            registration.setName("explicitSecondFilter");
            registration.addUrlPatterns("/protected/*");
            registration.setEnabled(true);
            return registration;
        }
    }

    static class StatusServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }
}
