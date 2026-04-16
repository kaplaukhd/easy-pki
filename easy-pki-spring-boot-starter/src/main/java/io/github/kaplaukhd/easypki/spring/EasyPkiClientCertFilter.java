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
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

import io.github.kaplaukhd.easypki.validation.ValidationResult;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Servlet filter that validates the client certificate presented during a
 * TLS handshake via {@link EasyPkiValidator}. Intended to run <em>before</em>
 * Spring Security's
 * {@code org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter}
 * so that signature and revocation checks happen before the subject DN is
 * used to load a user.
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain filterChain(HttpSecurity http,
 *                                 EasyPkiClientCertFilter easyPki) throws Exception {
 *     return http
 *         .x509(x509 -> x509.subjectPrincipalRegex("CN=(.*?)(?:,|$)"))
 *         .addFilterBefore(easyPki, X509AuthenticationFilter.class)
 *         .build();
 * }
 * }</pre>
 *
 * <p>When a request arrives with no client certificate and
 * {@code optional == false}, the filter responds with {@code 401 Unauthorized}.
 * When a certificate is present but fails validation, the filter responds
 * with {@code 401 Unauthorized} and the {@link ValidationResult} is attached
 * to the request under {@link #ATTRIBUTE_RESULT} for diagnostics. Successful
 * validations also store the result there.
 */
public final class EasyPkiClientCertFilter extends OncePerRequestFilter {

    /** Attribute key under which the {@link ValidationResult} is exposed. */
    public static final String ATTRIBUTE_RESULT = "easyPki.validationResult";

    /** Standard Servlet attribute containing the client certificate chain. */
    public static final String CLIENT_CERT_ATTRIBUTE =
            "jakarta.servlet.request.X509Certificate";

    private static final Logger LOG = LoggerFactory.getLogger(EasyPkiClientCertFilter.class);

    private final EasyPkiValidator validator;
    private final boolean optional;

    public EasyPkiClientCertFilter(EasyPkiValidator validator, boolean optional) {
        this.validator = Objects.requireNonNull(validator, "validator");
        this.optional = optional;
    }

    /** Convenience constructor — non-optional filter (rejects requests without certs). */
    public EasyPkiClientCertFilter(EasyPkiValidator validator) {
        this(validator, false);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        X509Certificate[] certs = extractCerts(request);
        if (certs == null || certs.length == 0) {
            if (optional) {
                chain.doFilter(request, response);
                return;
            }
            LOG.debug("Rejecting request: no client certificate on request to {}",
                    request.getRequestURI());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Client certificate required");
            return;
        }

        X509Certificate leaf = certs[0];
        X509Certificate[] rest = Arrays.copyOfRange(certs, 1, certs.length);

        ValidationResult result = validator.validate(leaf, rest);
        request.setAttribute(ATTRIBUTE_RESULT, result);

        if (!result.isValid()) {
            LOG.debug("Rejecting request to {}: client cert '{}' failed validation: {}",
                    request.getRequestURI(),
                    leaf.getSubjectX500Principal().getName(),
                    result.getErrors());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Client certificate rejected");
            return;
        }

        chain.doFilter(request, response);
    }

    private static X509Certificate[] extractCerts(HttpServletRequest request) {
        Object value = request.getAttribute(CLIENT_CERT_ATTRIBUTE);
        if (value instanceof X509Certificate[] arr) {
            return arr;
        }
        return null;
    }
}
