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

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches CRLs over HTTP with in-memory caching. Package-private.
 */
final class HttpCrlFetcher {

    private final HttpClient client;
    private final Duration timeout;
    private final Duration cacheTtl;
    private final ConcurrentHashMap<URI, CacheEntry> cache = new ConcurrentHashMap<>();

    HttpCrlFetcher(Duration timeout, URI proxy, Duration cacheTtl) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(timeout);
        if (proxy != null) {
            builder.proxy(ProxySelector.of(
                    new InetSocketAddress(proxy.getHost(), proxy.getPort())));
        }
        this.client = builder.build();
        this.timeout = timeout;
        this.cacheTtl = cacheTtl;
    }

    /**
     * Fetches the CRL at {@code url}, using the cache when possible.
     * Returns empty on any failure (network error, non-200 response, parse error).
     */
    Optional<X509CRL> fetch(URI url) {
        Instant now = Instant.now();
        CacheEntry entry = cache.get(url);
        if (entry != null && now.isBefore(entry.expiresAt)) {
            return Optional.of(entry.crl);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder(url)
                    .timeout(timeout)
                    .header("Accept", "application/pkix-crl, application/x-pkcs7-crl")
                    .GET()
                    .build();
            HttpResponse<byte[]> response = client.send(
                    request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                return Optional.empty();
            }
            X509CRL crl = parse(response.body());
            cache.put(url, new CacheEntry(crl, computeExpiry(now, crl)));
            return Optional.of(crl);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /** Removes all cached entries — exposed for tests. */
    void clearCache() {
        cache.clear();
    }

    int cacheSize() {
        return cache.size();
    }

    private Instant computeExpiry(Instant now, X509CRL crl) {
        Instant soft = now.plus(cacheTtl);
        if (crl.getNextUpdate() == null) {
            return soft;
        }
        Instant hard = crl.getNextUpdate().toInstant();
        return soft.isBefore(hard) ? soft : hard;
    }

    private static X509CRL parse(byte[] bytes) {
        // Try DER first (the most common encoding for CRL responses).
        try {
            return PkiCrls.fromDer(bytes);
        } catch (IllegalArgumentException ignored) {
            return PkiCrls.fromPem(new String(bytes, StandardCharsets.UTF_8));
        }
    }

    private record CacheEntry(X509CRL crl, Instant expiresAt) {}
}
