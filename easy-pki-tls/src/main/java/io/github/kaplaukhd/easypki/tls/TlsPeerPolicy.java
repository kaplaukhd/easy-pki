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
package io.github.kaplaukhd.easypki.tls;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Immutable TLS peer validation policy with an explicit revocation choice.
 * Every policy requires PKIX trust, a currently valid end-entity certificate,
 * explicit serverAuth or clientAuth EKU, and digitalSignature KeyUsage.
 * Server authentication additionally requires a matching DNS or IP SAN;
 * the subject Common Name is never used. Authenticating a client certificate
 * does not authorize that client to use application resources.
 *
 * <p>Reference DNS names must be ASCII, with internationalized names supplied
 * as A-labels. DNS matching is case-insensitive; a wildcard occupies the entire
 * leftmost label and matches exactly one label. IP matching preserves the
 * distinction between four-byte IPv4 and sixteen-byte IPv6 addresses. URI and
 * SRV service identifiers, reverse DNS and Common Name fallback are not supported.
 *
 * <p>This bounded JSSE adapter does not configure online OCSP, CRL retrieval
 * or stapled-response processing. Host JSSE algorithm constraints remain active.
 */
public final class TlsPeerPolicy {
    private final boolean checkRevocation;
    private final List<X509CRL> crls;

    private TlsPeerPolicy(boolean checkRevocation, List<X509CRL> crls) {
        this.checkRevocation = checkRevocation;
        this.crls = List.copyOf(crls);
    }

    /** Explicitly disables revocation checking while retaining all other peer checks. */
    public static TlsPeerPolicy withoutRevocationChecks() {
        return new TlsPeerPolicy(false, List.of());
    }

    /**
     * Requires a valid, applicable supplied CRL for every certificate below the
     * selected trust anchor. Missing, expired or unsupported revocation evidence
     * fails the handshake. CRLs are copied from their DER encodings and must have
     * thisUpdate and nextUpdate, with nextUpdate after thisUpdate. No network CRL
     * retrieval is enabled. Path selection allows at most 19 non-self-issued
     * intermediates, matching the validation module's bounded chain builder.
     * Use {@link ReloadableTlsContext#reloadPeerPolicy(TlsPeerPolicy)} to atomically
     * refresh the evidence for newly created connections.
     */
    public static TlsPeerPolicy withCrls(X509CRL... crls) {
        Objects.requireNonNull(crls, "crls");
        return withCrls(Arrays.asList(crls.clone()));
    }

    /** Collection overload of {@link #withCrls(X509CRL...)}. */
    public static TlsPeerPolicy withCrls(Collection<X509CRL> crls) {
        Objects.requireNonNull(crls, "crls");
        if (crls.isEmpty()) throw new IllegalArgumentException("CRL validation requires at least one CRL");
        List<X509CRL> snapshots = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (X509CRL crl : List.copyOf(crls)) {
                X509CRL snapshot = (X509CRL) factory.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
                if (snapshot.getThisUpdate() == null || snapshot.getNextUpdate() == null
                        || !snapshot.getNextUpdate().after(snapshot.getThisUpdate())) {
                    throw new IllegalArgumentException("TLS CRLs require nextUpdate after thisUpdate");
                }
                snapshots.add(snapshot);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot snapshot TLS CRL", e);
        }
        return new TlsPeerPolicy(true, snapshots);
    }

    /** Returns whether this policy requires offline CRL evidence. */
    public boolean isRevocationChecked() { return checkRevocation; }

    boolean checkRevocation() { return checkRevocation; }
    List<X509CRL> crls() { return crls; }
}
