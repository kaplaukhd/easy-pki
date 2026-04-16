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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An immutable, ordered certificate chain produced by {@link ChainBuilder}.
 *
 * <p>The first element is the end-entity (leaf), the last is the trust
 * anchor (self-signed root or an explicit anchor from the configured trust
 * store). Intermediate certificates, if any, sit between them in hierarchical
 * order.
 */
public final class CertChain {

    private final List<X509Certificate> certificates;
    private final X509Certificate anchor;

    CertChain(List<X509Certificate> certificates, X509Certificate anchor) {
        this.certificates = List.copyOf(certificates);
        this.anchor = anchor;
    }

    /** Returns the full chain, leaf first. */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    /** Returns the end-entity (leaf) certificate. */
    public X509Certificate getLeaf() {
        return certificates.get(0);
    }

    /** Returns the trust anchor at the top of the chain. */
    public X509Certificate getRoot() {
        return anchor;
    }

    /** Returns the number of certificates in the chain, including the anchor. */
    public int size() {
        return certificates.size();
    }

    /**
     * Returns a {@link CertValidator} pre-configured with this chain and the
     * trust anchor. Further calls like {@code .ocsp(...)} and {@code .crl(...)}
     * may be chained.
     */
    public CertValidator toValidator() {
        // Pass the chain excluding the leaf — CertValidator.of(cert).chain(rest)
        CertValidator v = CertValidator.of(getLeaf());
        List<X509Certificate> rest = certificates.subList(1, certificates.size());
        if (!rest.isEmpty()) {
            v = v.chain(rest);
        }
        v = v.trustAnchors(anchor);
        return v;
    }

    /**
     * Convenience for {@code toValidator().validate()} — performs chain-only
     * validation (no revocation).
     */
    public ValidationResult validate() {
        return toValidator().validate();
    }
}
