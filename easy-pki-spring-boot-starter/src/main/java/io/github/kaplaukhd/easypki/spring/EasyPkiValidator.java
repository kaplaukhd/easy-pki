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
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import io.github.kaplaukhd.easypki.validation.CertValidator;
import io.github.kaplaukhd.easypki.validation.ValidationResult;

/**
 * Application-facing validator pre-configured with trust anchors and the
 * revocation mode chosen via {@code easy-pki.validation.mode}.
 *
 * <p>Typical injection:
 * <pre>{@code
 * @Service
 * public class TlsService {
 *     private final EasyPkiValidator validator;
 *
 *     public TlsService(EasyPkiValidator validator) {
 *         this.validator = validator;
 *     }
 *
 *     public void check(X509Certificate clientCert, X509Certificate intermediate) {
 *         ValidationResult result = validator.validate(clientCert, intermediate);
 *         if (!result.isValid()) throw new SecurityException(result.getErrors().toString());
 *     }
 * }
 * }</pre>
 *
 * <p>The instance is thread-safe and reusable across requests. For advanced
 * per-call tuning (custom CRLs, explicit OCSP URL, evaluation time) obtain a
 * pre-configured builder via {@link #newValidator(X509Certificate)}.
 */
public final class EasyPkiValidator {

    private final List<X509Certificate> trustAnchors;
    private final ValidationMode mode;
    private final Duration ocspTimeout;
    private final Duration crlCacheTtl;
    private final Duration httpTimeout;
    private final String proxy;

    public EasyPkiValidator(Collection<X509Certificate> trustAnchors,
                            ValidationMode mode,
                            Duration ocspTimeout,
                            Duration crlCacheTtl,
                            Duration httpTimeout,
                            String proxy) {
        Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.trustAnchors = List.copyOf(trustAnchors);
        this.mode = Objects.requireNonNull(mode, "mode");
        this.ocspTimeout = Objects.requireNonNull(ocspTimeout, "ocspTimeout");
        this.crlCacheTtl = Objects.requireNonNull(crlCacheTtl, "crlCacheTtl");
        this.httpTimeout = Objects.requireNonNull(httpTimeout, "httpTimeout");
        this.proxy = proxy;
    }

    /** Validates a certificate against the configured trust anchors and mode. */
    public ValidationResult validate(X509Certificate certificate) {
        return newValidator(certificate).validate();
    }

    /** Validates a certificate with an explicit chain (intermediates and root, if any). */
    public ValidationResult validate(X509Certificate certificate, X509Certificate... chain) {
        Objects.requireNonNull(chain, "chain");
        CertValidator v = newValidator(certificate);
        if (chain.length > 0) {
            v = v.chain(chain);
        }
        return v.validate();
    }

    /** Validates a certificate with an explicit chain as a list. */
    public ValidationResult validate(X509Certificate certificate, List<X509Certificate> chain) {
        Objects.requireNonNull(chain, "chain");
        CertValidator v = newValidator(certificate);
        if (!chain.isEmpty()) {
            v = v.chain(chain);
        }
        return v.validate();
    }

    /**
     * Returns a fluent {@link CertValidator} pre-wired with the configured
     * trust anchors and revocation mode, for cases where the caller needs
     * additional options (custom CRLs, evaluation time, etc.).
     */
    public CertValidator newValidator(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        CertValidator v = CertValidator.of(certificate).trustAnchors(trustAnchors);
        switch (mode) {
            case NONE -> {
                // no-op
            }
            case OCSP -> v.ocsp(o -> {
                o.timeout(ocspTimeout);
                if (hasProxy()) {
                    o.proxy(proxy);
                }
            });
            case CRL -> v.crl(c -> {
                c.autoFetch().cache(crlCacheTtl).timeout(httpTimeout);
                if (hasProxy()) {
                    c.proxy(proxy);
                }
            });
            case OCSP_WITH_CRL_FALLBACK -> {
                v.ocsp(o -> {
                    o.timeout(ocspTimeout);
                    if (hasProxy()) {
                        o.proxy(proxy);
                    }
                });
                v.crl(c -> {
                    c.autoFetch().cache(crlCacheTtl).timeout(httpTimeout);
                    if (hasProxy()) {
                        c.proxy(proxy);
                    }
                });
            }
        }
        return v;
    }

    /** Returns the configured trust anchors (immutable snapshot). */
    public List<X509Certificate> getTrustAnchors() {
        return trustAnchors;
    }

    /** Returns the configured validation mode. */
    public ValidationMode getMode() {
        return mode;
    }

    private boolean hasProxy() {
        return proxy != null && !proxy.isBlank();
    }
}
