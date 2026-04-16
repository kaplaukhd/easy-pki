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
package io.github.kaplaukhd.easypki.validation;

import java.net.URI;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Configuration object for CRL-based revocation checking. Obtained via
 * {@link CertValidator#crl(java.util.function.Consumer)}.
 *
 * <pre>{@code
 * CertValidator.of(cert)
 *     .chain(intermediate, root)
 *     .crl(c -> c.autoFetch()
 *                .cache(Duration.ofMinutes(30))
 *                .timeout(Duration.ofSeconds(10))
 *                .proxy("http://proxy.corp:3128"))
 *     .validate();
 * }</pre>
 *
 * <p>Static CRLs added via {@link #add(X509CRL...)} (or the shorthand
 * {@link CertValidator#crl(X509CRL...)}) are always consulted first. When no
 * static CRL matches a certificate and {@link #autoFetch() auto-fetch} is
 * enabled, the validator downloads a CRL from each URL listed in the
 * certificate's CRL Distribution Points extension.
 */
public final class CrlConfig {

    private final List<X509CRL> staticCrls = new ArrayList<>();
    private boolean autoFetch;
    private Duration cacheTtl = Duration.ofHours(1);
    private Duration httpTimeout = Duration.ofSeconds(10);
    private URI proxy;

    CrlConfig() {
        // Package-private — obtained through CertValidator.
    }

    /** Registers static CRLs. Multiple calls accumulate. */
    public CrlConfig add(X509CRL... crls) {
        Objects.requireNonNull(crls, "crls");
        for (X509CRL crl : crls) {
            this.staticCrls.add(Objects.requireNonNull(crl, "crl"));
        }
        return this;
    }

    /** List overload of {@link #add(X509CRL...)}. */
    public CrlConfig add(List<X509CRL> crls) {
        Objects.requireNonNull(crls, "crls");
        for (X509CRL crl : crls) {
            this.staticCrls.add(Objects.requireNonNull(crl, "crl"));
        }
        return this;
    }

    /** Enables fetching CRLs from URLs listed in each certificate's CDP extension. */
    public CrlConfig autoFetch() {
        this.autoFetch = true;
        return this;
    }

    /** Toggles auto-fetch explicitly. */
    public CrlConfig autoFetch(boolean enabled) {
        this.autoFetch = enabled;
        return this;
    }

    /**
     * Sets the maximum time a fetched CRL is cached before being re-downloaded.
     * The effective TTL is the shorter of this value and the CRL's own
     * {@code nextUpdate}. Default: 1 hour.
     */
    public CrlConfig cache(Duration ttl) {
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("cache TTL must be positive, got " + ttl);
        }
        this.cacheTtl = ttl;
        return this;
    }

    /** Per-request HTTP timeout for CRL fetches. Default: 10 seconds. */
    public CrlConfig timeout(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive, got " + timeout);
        }
        this.httpTimeout = timeout;
        return this;
    }

    /**
     * HTTP proxy for CRL fetches, e.g. {@code "http://proxy.corp:3128"}.
     * Scheme is ignored; only host and port are used.
     */
    public CrlConfig proxy(String url) {
        Objects.requireNonNull(url, "url");
        this.proxy = URI.create(url);
        if (this.proxy.getHost() == null || this.proxy.getPort() < 0) {
            throw new IllegalArgumentException(
                    "Proxy URL must include host and port: " + url);
        }
        return this;
    }

    /** Removes any previously configured proxy. */
    public CrlConfig noProxy() {
        this.proxy = null;
        return this;
    }

    // ---------- package-private accessors ----------

    List<X509CRL> staticCrls() {
        return staticCrls;
    }

    boolean isAutoFetch() {
        return autoFetch;
    }

    Duration cacheTtl() {
        return cacheTtl;
    }

    Duration httpTimeout() {
        return httpTimeout;
    }

    URI proxy() {
        return proxy;
    }
}
