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
import java.security.KeyStore;
import java.util.Optional;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * A coherent, fixed identity/trust generation. Managers and read-only stores expose
 * this generation only: initializing an unrelated SSLContext with them does not enable rotation.
 * Private key handles remain application-owned and are never exported or destroyed.
 */
public final class TlsSnapshot {
    private final long generation;
    private final PkiIdentity identity;
    private final TrustBundle trust;
    private final KeyStore keys;
    private final KeyStore anchors;
    private final KeyManager[] keyManagers;
    private final TrustManager[] trustManagers;
    private final SSLContext context;

    TlsSnapshot(long generation, PkiIdentity identity, TrustBundle trust, KeyStore keys, KeyStore anchors,
                KeyManager[] keyManagers, TrustManager[] trustManagers, SSLContext context) {
        this.generation = generation; this.identity = identity; this.trust = trust;
        this.keys = keys; this.anchors = anchors; this.keyManagers = keyManagers.clone();
        this.trustManagers = trustManagers.clone(); this.context = context;
    }
    /** Returns the monotonically increasing publication number, starting at zero. */
    public long getGeneration() { return generation; }
    /** Returns the local identity; empty for a client which presents no certificate. */
    public Optional<PkiIdentity> getIdentity() { return Optional.ofNullable(identity); }
    /** Returns the explicit peer trust snapshot. */
    public TrustBundle getTrustBundle() { return trust; }
    /** Returns a copy of the array of fixed-generation key managers. */
    public KeyManager[] getKeyManagers() { return keyManagers.clone(); }
    /** Returns a copy of the array of fixed-generation trust managers. */
    public TrustManager[] getTrustManagers() { return trustManagers.clone(); }
    /**
     * Returns a read-only, nonserializable key-handle store; empty without an identity.
     * Known BC Ed25519 software keys use a nonserializable standard EdEC interface view
     * with the EdDSA label expected by SunJSSE. Other handles are retained unchanged.
     */
    public KeyStore getKeyStore() { return keys; }
    /** Returns a read-only store containing only explicitly selected peer anchors. */
    public KeyStore getTrustStore() { return anchors; }
    SSLContext context() { return context; }
}
