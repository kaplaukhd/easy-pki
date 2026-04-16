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

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Builds an ordered certificate chain from an end-entity certificate by
 * looking up issuers in a pool of intermediates and terminating in a trust
 * anchor.
 *
 * <pre>{@code
 * CertChain chain = ChainBuilder.of(leafCert)
 *     .intermediates(pool)          // Collection<X509Certificate>
 *     .trustAnchors(rootA, rootB)   // or .trustStore(keyStore)
 *     .build();                     // throws if no path is found
 *
 * ValidationResult result = chain.validate();
 * }</pre>
 *
 * <p>The algorithm walks from the leaf upward, at each step choosing a
 * candidate whose subject DN matches the current certificate's issuer DN and
 * whose public key verifies the current certificate's signature. Termination
 * is reached when an explicit trust anchor is matched, or when a self-signed
 * certificate in the trust anchors is encountered.
 */
public final class ChainBuilder {

    private static final int MAX_DEPTH = 20;

    private final X509Certificate certificate;
    private final Set<X509Certificate> intermediates = new LinkedHashSet<>();
    private final Set<X509Certificate> trustAnchors = new LinkedHashSet<>();

    private ChainBuilder(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /** Starts chain building for the given end-entity certificate. */
    public static ChainBuilder of(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        return new ChainBuilder(certificate);
    }

    /** Adds candidate intermediate certificates. Multiple calls accumulate. */
    public ChainBuilder intermediates(X509Certificate... certs) {
        Objects.requireNonNull(certs, "certs");
        intermediates.addAll(Arrays.asList(certs));
        return this;
    }

    /** Collection overload of {@link #intermediates(X509Certificate...)}. */
    public ChainBuilder intermediates(Collection<X509Certificate> certs) {
        Objects.requireNonNull(certs, "certs");
        intermediates.addAll(certs);
        return this;
    }

    /** Adds explicit trust anchors. Multiple calls accumulate. */
    public ChainBuilder trustAnchors(X509Certificate... anchors) {
        Objects.requireNonNull(anchors, "anchors");
        trustAnchors.addAll(Arrays.asList(anchors));
        return this;
    }

    /** Collection overload of {@link #trustAnchors(X509Certificate...)}. */
    public ChainBuilder trustAnchors(Collection<X509Certificate> anchors) {
        Objects.requireNonNull(anchors, "anchors");
        trustAnchors.addAll(anchors);
        return this;
    }

    /**
     * Reads trust anchors from a JCA {@link KeyStore}. All certificate entries
     * are added as anchors; key entries are ignored.
     */
    public ChainBuilder trustStore(KeyStore keyStore) {
        Objects.requireNonNull(keyStore, "keyStore");
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!keyStore.isCertificateEntry(alias)) {
                    continue;
                }
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x) {
                    trustAnchors.add(x);
                }
            }
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to read trust store", e);
        }
        return this;
    }

    /**
     * Builds the chain from the configured leaf, intermediates and anchors.
     *
     * @throws IllegalStateException if no path can be built, the chain exceeds
     *         {@value #MAX_DEPTH} levels, or required inputs are missing.
     */
    public CertChain build() {
        if (trustAnchors.isEmpty()) {
            throw new IllegalStateException(
                    "At least one trust anchor (or a trust store) is required");
        }

        List<X509Certificate> path = new ArrayList<>();
        path.add(certificate);

        Set<X509Certificate> remaining = new HashSet<>(intermediates);
        X509Certificate current = certificate;

        for (int depth = 0; depth < MAX_DEPTH; depth++) {
            // 1) If the current cert is already a trust anchor, we're done.
            X509Certificate anchor = matchingAnchor(current);
            if (anchor != null) {
                // The current cert is the anchor itself — nothing to append.
                return new CertChain(path, current);
            }

            // 2) Try to find the issuer among the explicit trust anchors.
            for (X509Certificate a : trustAnchors) {
                if (signedBy(current, a)) {
                    path.add(a);
                    return new CertChain(path, a);
                }
            }

            // 3) Otherwise, find it in the intermediate pool.
            X509Certificate parent = null;
            for (X509Certificate candidate : remaining) {
                if (signedBy(current, candidate)) {
                    parent = candidate;
                    break;
                }
            }
            if (parent == null) {
                throw new IllegalStateException(
                        "Unable to build chain: no issuer found for '"
                                + current.getSubjectX500Principal().getName() + "'");
            }
            path.add(parent);
            remaining.remove(parent);
            current = parent;
        }
        throw new IllegalStateException(
                "Chain exceeds maximum depth of " + MAX_DEPTH);
    }

    /**
     * Returns the trust anchor that equals {@code cert}, or {@code null} if
     * none matches. Equality is by certificate identity (encoded form).
     */
    private X509Certificate matchingAnchor(X509Certificate cert) {
        for (X509Certificate a : trustAnchors) {
            if (a.equals(cert)) {
                return a;
            }
        }
        return null;
    }

    private static boolean signedBy(X509Certificate child, X509Certificate candidateParent) {
        if (!candidateParent.getSubjectX500Principal()
                .equals(child.getIssuerX500Principal())) {
            return false;
        }
        try {
            child.verify(candidateParent.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
