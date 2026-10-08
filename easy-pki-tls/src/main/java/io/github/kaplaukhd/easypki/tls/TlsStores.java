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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/** Handle-based stores; no private key serialization or global provider registration. */
final class TlsStores extends KeyStore {
    static final Provider PROVIDER = new Provider("easy-pki-tls", "1.0", "Local TLS adapters") {
        private static final long serialVersionUID = 1L;
    };
    private TlsStores(Store store) { super(store, PROVIDER, "easy-pki-memory"); }
    static KeyStore keys(PkiIdentity identity) { return loaded(new Store(identity, null)); }
    static KeyStore trust(TrustBundle trust) { return loaded(new Store(null, trust)); }
    private static KeyStore loaded(Store store) {
        try {
            KeyStore result = new TlsStores(store);
            result.load(null, null);
            return result;
        } catch (java.security.GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot initialize TLS material store", e);
        }
    }
    private static final class Store extends KeyStoreSpi {
        private final PrivateKey key;
        private final Certificate[] chain;
        private final Map<String, Certificate> certificates = new LinkedHashMap<>();
        Store(PkiIdentity identity, TrustBundle trust) {
            key = identity == null ? null : TlsKeySupport.forJsse(identity.getPrivateKey().orElseThrow(
                    () -> new IllegalArgumentException("JSSE needs a JCA PrivateKey handle; signer-only identities are unsupported")));
            chain = identity == null ? new Certificate[0] : identity.getChain().toArray(X509Certificate[]::new);
            if (identity != null) certificates.put("identity", chain[0]);
            if (trust != null) {
                int index = 0;
                for (X509Certificate certificate : trust.getTrustAnchors()) certificates.put("trust-" + index++, certificate);
            }
        }
        @Override public Key engineGetKey(String alias, char[] password) { return engineIsKeyEntry(alias) ? key : null; }
        @Override public Certificate[] engineGetCertificateChain(String alias) { return engineIsKeyEntry(alias) ? chain.clone() : null; }
        @Override public Certificate engineGetCertificate(String alias) { return certificates.get(alias); }
        @Override public Date engineGetCreationDate(String alias) { return certificates.containsKey(alias) ? new Date(0) : null; }
        @Override public Enumeration<String> engineAliases() { return Collections.enumeration(certificates.keySet()); }
        @Override public boolean engineContainsAlias(String alias) { return certificates.containsKey(alias); }
        @Override public int engineSize() { return certificates.size(); }
        @Override public boolean engineIsKeyEntry(String alias) { return key != null && "identity".equals(alias); }
        @Override public boolean engineIsCertificateEntry(String alias) { return certificates.containsKey(alias) && !engineIsKeyEntry(alias); }
        @Override public String engineGetCertificateAlias(Certificate certificate) {
            for (var entry : certificates.entrySet()) if (entry.getValue().equals(certificate)) return entry.getKey();
            return null;
        }
        @Override public void engineSetKeyEntry(String alias, Key value, char[] password, Certificate[] values) throws KeyStoreException { throw immutable(); }
        @Override public void engineSetKeyEntry(String alias, byte[] value, Certificate[] values) throws KeyStoreException { throw immutable(); }
        @Override public void engineSetCertificateEntry(String alias, Certificate value) throws KeyStoreException { throw immutable(); }
        @Override public void engineDeleteEntry(String alias) throws KeyStoreException { throw immutable(); }
        @Override public void engineStore(OutputStream stream, char[] password) throws IOException { throw new IOException("TLS handle stores cannot be serialized"); }
        @Override public void engineLoad(InputStream stream, char[] password) throws IOException {
            if (stream != null) throw new IOException("TLS material stores are immutable");
        }
        private static KeyStoreException immutable() { return new KeyStoreException("TLS material stores are read-only"); }
    }
}
