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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class EasyPkiClientCertFilterTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair leafKeys;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Filter Test Root")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(3650))
                .isCA(true)
                .build();
        leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=client")
                .publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .build();
    }

    private EasyPkiValidator validator(X509Certificate anchor) {
        return new EasyPkiValidator(
                anchor != null ? List.of(anchor) : List.of(),
                ValidationMode.NONE,
                Duration.ofSeconds(5),
                Duration.ofMinutes(30),
                Duration.ofSeconds(10),
                null);
    }

    @Test
    void validCertPassesThrough() throws Exception {
        EasyPkiClientCertFilter filter = new EasyPkiClientCertFilter(validator(root));
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/secure");
        req.setAttribute(EasyPkiClientCertFilter.CLIENT_CERT_ATTRIBUTE,
                new X509Certificate[]{leaf, root});
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(chain.getRequest()).as("downstream request reached").isNotNull();
        ValidationResult result = (ValidationResult)
                req.getAttribute(EasyPkiClientCertFilter.ATTRIBUTE_RESULT);
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void missingCertProducesUnauthorized() throws Exception {
        EasyPkiClientCertFilter filter = new EasyPkiClientCertFilter(validator(root));
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/secure");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(chain.getRequest()).as("chain not invoked").isNull();
    }

    @Test
    void missingCertInOptionalModePassesThrough() throws Exception {
        EasyPkiClientCertFilter filter = new EasyPkiClientCertFilter(validator(root), true);
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/optional");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void invalidCertProducesUnauthorized() throws Exception {
        // Use a different, unrelated anchor — our chain's root won't match.
        KeyPair otherKeys = PkiKeys.rsa(2048);
        X509Certificate otherRoot = PkiCertificate.selfSigned()
                .subject("CN=Unrelated")
                .keyPair(otherKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true).build();

        EasyPkiClientCertFilter filter = new EasyPkiClientCertFilter(validator(otherRoot));
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/secure");
        req.setAttribute(EasyPkiClientCertFilter.CLIENT_CERT_ATTRIBUTE,
                new X509Certificate[]{leaf, root});
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        ValidationResult result = (ValidationResult)
                req.getAttribute(EasyPkiClientCertFilter.ATTRIBUTE_RESULT);
        assertThat(result).as("result still attached for diagnostics").isNotNull();
        assertThat(result.isValid()).isFalse();
    }
}
