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
package io.github.kaplaukhd.easypki.test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import io.github.kaplaukhd.easypki.spring.EasyPkiAutoConfiguration;
import io.github.kaplaukhd.easypki.spring.EasyPkiClientCertFilter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// --8<-- [start:spring-example]
@SpringBootTest(classes = WebSecurityExampleTest.Application.class)
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class WebSecurityExampleTest {
    // One CA for both context initialization and every test method.
    private static final TestPki PKI = TestPki.create().withRootCa("CN=Web Test CA").build();
    private static final Path TRUST_STORE = createTrustStore();

    @Autowired MockMvc mvc;

    @DynamicPropertySource
    static void trustStore(DynamicPropertyRegistry registry) {
        registry.add("easy-pki.trust-store.path", () -> TRUST_STORE.toUri().toString());
        registry.add("easy-pki.trust-store.password", () -> "test-password");
        registry.add("easy-pki.validation.mode", () -> "NONE");
    }

    @ParameterizedTest
    @ValueSource(strings = {"first-client", "second-client"})
    void trustedClientsAreAccepted(String name) throws Exception {
        X509Certificate client = PKI.issueCert().subject("CN=" + name).build();
        mvc.perform(get("/protected").requestAttr("jakarta.servlet.request.X509Certificate",
                new X509Certificate[]{client})).andExpect(status().isOk());
    }

    @Test
    void missingClientCertificateIsRejected() throws Exception {
        mvc.perform(get("/protected")).andExpect(status().isUnauthorized());
    }

    @Test
    void anotherCaIsRejected() throws Exception {
        TestPki other = TestPki.create().withRootCa("CN=Other CA").build();
        X509Certificate client = other.issueCert().subject("CN=untrusted").build();
        mvc.perform(get("/protected").requestAttr("jakarta.servlet.request.X509Certificate",
                new X509Certificate[]{client})).andExpect(status().isUnauthorized());
    }

    private static Path createTrustStore() {
        try {
            Path path = Files.createTempFile("easy-pki-web-test-", ".p12");
            try {
                PkiPkcs12.create().certificate(PKI.getRootCa()).password("test-password")
                        .build().saveTo(path);
                return path;
            } catch (RuntimeException | Error e) {
                Files.deleteIfExists(path);
                throw e;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @AfterAll
    static void deleteTrustStore() throws IOException {
        Files.deleteIfExists(TRUST_STORE);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Endpoint.class)
    static class Application {
        // Explicit opt-in; the starter alone does not register protection.
        @Bean(EasyPkiAutoConfiguration.SecurityConfiguration.FILTER_REGISTRATION_BEAN)
        FilterRegistrationBean<EasyPkiClientCertFilter> clientCertificates(EasyPkiClientCertFilter filter) {
            var registration = new FilterRegistrationBean<>(filter);
            registration.addUrlPatterns("/protected");
            return registration;
        }
    }

    @RestController
    static class Endpoint {
        @GetMapping("/protected")
        String protectedResource() { return "ok"; }
    }
}
// --8<-- [end:spring-example]
