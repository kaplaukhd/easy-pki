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
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
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
 * <p>Uses the JCA PKIX path builder to find a valid path to an explicitly
 * configured trust anchor, considering alternative issuer certificates when
 * a candidate path fails. Certificates in the intermediate pool do not become
 * trusted merely because they are self-signed. The returned chain includes
 * its anchor, which can also be an explicitly trusted intermediate or target
 * certificate.
 *
 * <p>PKIX checks validity at the current time and certificate constraints for
 * certificates below the trust anchor.
 * Revocation checking is disabled during building; configure it separately
 * through {@link CertChain#toValidator()} when needed.
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

    /** Adds candidate intermediates. Multiple calls accumulate; nulls are rejected. */
    public ChainBuilder intermediates(X509Certificate... certs) {
        Objects.requireNonNull(certs, "certs");
        return intermediates(Arrays.asList(certs));
    }

    /** Collection overload of {@link #intermediates(X509Certificate...)}. */
    public ChainBuilder intermediates(Collection<X509Certificate> certs) {
        Objects.requireNonNull(certs, "certs");
        intermediates.addAll(List.copyOf(certs));
        return this;
    }

    /** Adds explicit trust anchors. Multiple calls accumulate; nulls are rejected. */
    public ChainBuilder trustAnchors(X509Certificate... anchors) {
        Objects.requireNonNull(anchors, "anchors");
        return trustAnchors(Arrays.asList(anchors));
    }

    /** Collection overload of {@link #trustAnchors(X509Certificate...)}. */
    public ChainBuilder trustAnchors(Collection<X509Certificate> anchors) {
        Objects.requireNonNull(anchors, "anchors");
        trustAnchors.addAll(List.copyOf(anchors));
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
     * <p>At most 19 non-self-issued intermediate certificates are allowed,
     * excluding the target and trust anchor. An explicitly trusted target
     * produces a one-certificate chain without requiring its issuer.
     *
     * @throws IllegalStateException if no valid path can be built within the
     *         depth limit, or no trust anchors are configured. PKIX failures
     *         are retained as the cause.
     */
    public CertChain build() {
        if (trustAnchors.isEmpty()) {
            throw new IllegalStateException(
                    "At least one trust anchor (or a trust store) is required");
        }

        // A trust anchor is input to PKIX, not a certificate in the path.
        // Handle an explicitly trusted target without requiring it to be a CA.
        if (trustAnchors.contains(certificate)) {
            return new CertChain(List.of(certificate), certificate);
        }

        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        for (X509Certificate anchor : trustAnchors) {
            anchors.add(new TrustAnchor(anchor, null));
        }
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(certificate);
        try {
            PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, target);
            parameters.setRevocationEnabled(false);
            // Preserve the existing allowance of 19 intermediates rather than
            // inheriting PKIXBuilderParameters' default limit of five.
            parameters.setMaxPathLength(MAX_DEPTH - 1);
            List<X509Certificate> candidates = new ArrayList<>(intermediates);
            candidates.add(certificate);
            parameters.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(candidates)));

            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)
                    CertPathBuilder.getInstance("PKIX").build(parameters);
            List<X509Certificate> path = new ArrayList<>();
            for (Certificate cert : result.getCertPath().getCertificates()) {
                path.add((X509Certificate) cert);
            }
            X509Certificate anchor = result.getTrustAnchor().getTrustedCert();
            path.add(anchor);
            return new CertChain(path, anchor);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Unable to build a valid certificate path to a configured trust anchor", e);
        }
    }
}
