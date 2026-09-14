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
import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for OCSP-based revocation checking. Obtained via
 * {@link CertValidator#ocsp(java.util.function.Consumer)}.
 *
 * <pre>{@code
 * CertValidator.of(cert)
 *     .chain(intermediate, root)
 *     .trustAnchors(root) // configured by the application, not taken from the peer
 *     .ocsp(o -> o.url("http://ocsp.corp.internal")
 *                 .timeout(Duration.ofSeconds(5))
 *                 .proxy("http://proxy.corp:3128"))
 *     .validate();
 * }</pre>
 *
 * <p>When a URL is not set explicitly, the responder is taken from each
 * certificate's Authority Information Access (AIA) extension.
 *
 * <p>Response freshness is checked at the same instant as certificate validity,
 * including an explicit {@link CertValidator#at(java.time.Instant)}. By default,
 * clock skew of up to five minutes is allowed. If {@code nextUpdate} is absent,
 * {@code thisUpdate} may be at most 24 hours old, plus that skew. These are
 * library policy defaults and can be configured below. Freshness is checked
 * even when nonce checking is disabled.
 */
public final class OcspConfig {

    private URI url;
    private Duration timeout = Duration.ofSeconds(10);
    private URI proxy;
    private boolean nonceEnabled = true;
    private Duration clockSkew = Duration.ofMinutes(5);
    private Duration maxResponseAge = Duration.ofHours(24);

    OcspConfig() {
        // Package-private.
    }

    /**
     * Overrides the OCSP responder URL. By default the URL is read from
     * each certificate's AIA extension.
     */
    public OcspConfig url(String url) {
        Objects.requireNonNull(url, "url");
        this.url = URI.create(url);
        if (this.url.getScheme() == null
                || !(this.url.getScheme().equalsIgnoreCase("http")
                        || this.url.getScheme().equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("OCSP URL must be http or https: " + url);
        }
        return this;
    }

    /** Per-request HTTP timeout. Default: 10 seconds. */
    public OcspConfig timeout(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive, got " + timeout);
        }
        this.timeout = timeout;
        return this;
    }

    /**
     * HTTP proxy for OCSP requests, e.g. {@code "http://proxy.corp:3128"}.
     * Scheme is ignored; host and port are used.
     */
    public OcspConfig proxy(String url) {
        Objects.requireNonNull(url, "url");
        this.proxy = URI.create(url);
        if (this.proxy.getHost() == null || this.proxy.getPort() < 0) {
            throw new IllegalArgumentException(
                    "Proxy URL must include host and port: " + url);
        }
        return this;
    }

    /** Removes any previously configured proxy. */
    public OcspConfig noProxy() {
        this.proxy = null;
        return this;
    }

    /**
     * Controls whether a random nonce is sent with each request. When enabled
     * (the default), the response's nonce must match. Some responders do not
     * support nonces — disable when interoperating with those.
     */
    public OcspConfig nonce(boolean enabled) {
        this.nonceEnabled = enabled;
        return this;
    }

    /**
     * Sets the allowed clock difference for response freshness. Default: five
     * minutes. Must be nonnegative; zero requires exact timestamp boundaries.
     * Neither {@code thisUpdate} nor {@code producedAt} may be later than the
     * evaluation instant plus this allowance. A {@code nextUpdate} expiration
     * or the maximum response age is also extended by this allowance.
     */
    public OcspConfig clockSkew(Duration clockSkew) {
        Objects.requireNonNull(clockSkew, "clockSkew");
        if (clockSkew.isNegative()) {
            throw new IllegalArgumentException("clockSkew must be nonnegative, got " + clockSkew);
        }
        this.clockSkew = clockSkew;
        return this;
    }

    /**
     * Limits the age of {@code thisUpdate} when {@code nextUpdate} is absent.
     * Default: 24 hours. Must be positive. The configured {@link #clockSkew(Duration)}
     * is added to this allowance. When present, {@code nextUpdate} determines
     * expiration instead, and must not precede {@code thisUpdate}.
     */
    public OcspConfig maxResponseAge(Duration maxResponseAge) {
        Objects.requireNonNull(maxResponseAge, "maxResponseAge");
        if (maxResponseAge.isNegative() || maxResponseAge.isZero()) {
            throw new IllegalArgumentException("maxResponseAge must be positive, got " + maxResponseAge);
        }
        this.maxResponseAge = maxResponseAge;
        return this;
    }

    // ---------- package-private accessors ----------

    URI url() {
        return url;
    }

    Duration timeout() {
        return timeout;
    }

    URI proxy() {
        return proxy;
    }

    boolean isNonceEnabled() {
        return nonceEnabled;
    }

    Duration clockSkew() {
        return clockSkew;
    }

    Duration maxResponseAge() {
        return maxResponseAge;
    }
}
