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

import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.TrustBundle;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

final class TlsMaterialSupport {
    private TlsMaterialSupport() {}
    static TlsSnapshot prepare(long generation, PkiIdentity identity, TrustBundle trust, TlsPeerPolicy policy) {
        try {
            if (identity != null) validateIdentity(identity);
            KeyStore keys = TlsStores.keys(identity);
            KeyStore anchors = TlsStores.trust(trust);
            KeyManager[] keyManagers = new KeyManager[0];
            if (identity != null) {
                KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                factory.init(keys, new char[0]);
                keyManagers = factory.getKeyManagers();
            }
            TrustManager[] trustManagers = {TlsTrustManagers.create(trust, policy)};
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, null);
            return new TlsSnapshot(generation, identity, trust, keys, anchors, keyManagers, trustManagers, context);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot prepare TLS identity/trust material", e);
        }
    }
    private static void validateIdentity(PkiIdentity identity) throws GeneralSecurityException {
        if (identity.getPrivateKey().isEmpty()) {
            throw new IllegalArgumentException("JSSE requires a JCA PrivateKey handle; a PkiSigner alone cannot be used by TLS");
        }
        Date now = new Date();
        List<X509Certificate> chain = identity.getChain();
        for (X509Certificate certificate : chain) {
            certificate.checkValidity(now);
            if (certificate.hasUnsupportedCriticalExtension()) {
                throw new IllegalArgumentException("TLS identity chain contains an unsupported critical extension");
            }
        }
        X509Certificate leaf = identity.getCertificate();
        if (leaf.getBasicConstraints() >= 0) throw new IllegalArgumentException("TLS identity must be an end-entity certificate");
        boolean[] usage = leaf.getKeyUsage();
        List<String> purposes = leaf.getExtendedKeyUsage();
        if (usage == null || usage.length == 0 || !usage[0] || purposes == null
                || !(purposes.contains("1.3.6.1.5.5.7.3.1") || purposes.contains("1.3.6.1.5.5.7.3.2"))) {
            throw new IllegalArgumentException("TLS identity requires digitalSignature and explicit serverAuth or clientAuth");
        }
        for (int index = 1; index < chain.size(); index++) {
            X509Certificate issuer = chain.get(index);
            boolean[] issuerUsage = issuer.getKeyUsage();
            if (issuer.getBasicConstraints() < 0 || issuerUsage == null || issuerUsage.length <= 5 || !issuerUsage[5]) {
                throw new IllegalArgumentException("TLS identity chain contains an issuer without CA signing authority");
            }
            long subCas = chain.subList(1, index).stream().filter(cert ->
                    !cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())).count();
            if (subCas > issuer.getBasicConstraints()) throw new IllegalArgumentException("TLS identity chain exceeds issuer path length");
        }
        if (chain.size() > 1) {
            X509Certificate terminal = chain.get(chain.size() - 1);
            // The terminal certificate is a local consistency boundary, not peer trust.
            // JCA does not process anchor extensions; unsupported terminal constraints fail closed.
            Set<String> critical = terminal.getCriticalExtensionOIDs();
            if (critical != null && !Set.of("2.5.29.19", "2.5.29.15").containsAll(critical)) {
                throw new IllegalArgumentException("Unsupported critical extension on terminal identity-chain certificate");
            }
            for (String oid : List.of("2.5.29.30", "2.5.29.33", "2.5.29.36", "2.5.29.54")) {
                if (terminal.getExtensionValue(oid) != null) throw new IllegalArgumentException("Unsupported terminal identity-chain constraint: " + oid);
            }
            var path = CertificateFactory.getInstance("X.509").generateCertPath(chain.subList(0, chain.size() - 1));
            var parameters = new PKIXParameters(Set.of(new TrustAnchor(terminal, null)));
            parameters.setRevocationEnabled(false);
            parameters.setDate(now);
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
        }
    }
}
