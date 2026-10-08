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
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

/**
 * Atomically publishes complete TLS generations. Each successful update initializes a fresh
 * SSLContext with separate session/ticket state before publication. Failed updates retain the
 * previous generation. Writers serialize; readers and connection creation do not lock.
 *
 * <p>Sockets and engines capture a generation when created; a listening server socket captures
 * one after each TCP accept. Already created connections, including delayed handshakes and
 * established pooled connections, retain their generation. Updates do not close them or destroy
 * their application-owned key handles. Callers must drain old connections if immediate revocation
 * of existing connections is required. Do not cache managers to create an unrelated context and
 * expect it to rotate; use the stable context returned by {@link #getSslContext()}.
 */
public final class ReloadableTlsContext {
    private TlsPeerPolicy policy;
    private final AtomicReference<TlsSnapshot> current;
    private final SSLContext facade;

    ReloadableTlsContext(PkiIdentity identity, TrustBundle trust, TlsPeerPolicy policy) {
        this.policy = policy;
        current = new AtomicReference<>(TlsMaterialSupport.prepare(0, identity, trust, policy));
        facade = new LiveSslContext(current::get);
    }
    /**
     * Returns a stable context with generation-aware factories and engines. Reinitialization
     * is rejected. Defaults are TLS 1.3/1.2; server sockets and engines require client certificates
     * unless their caller explicitly changes client-auth settings. Client callers must supply
     * the intended peer host when creating/connecting sockets or creating engines.
     */
    public SSLContext getSslContext() { return facade; }
    /** Returns one coherent fixed-generation material snapshot. */
    public TlsSnapshot getSnapshot() { return current.get(); }
    /** Validates and publishes a new identity while retaining the latest peer trust. */
    public synchronized TlsSnapshot reloadIdentity(PkiIdentity identity) {
        return publish(Objects.requireNonNull(identity, "identity"), current.get().getTrustBundle());
    }
    /** Validates and publishes new peer trust while retaining the latest identity. Empty trust denies all peers. */
    public synchronized TlsSnapshot reloadTrust(TrustBundle trust) {
        return publish(current.get().getIdentity().orElse(null), Objects.requireNonNull(trust, "trust"));
    }
    /** Validates and publishes identity and trust together, with no intermediate combination visible. */
    public synchronized TlsSnapshot reload(PkiIdentity identity, TrustBundle trust) {
        return publish(Objects.requireNonNull(identity, "identity"), Objects.requireNonNull(trust, "trust"));
    }
    /** Replaces peer policy, for example with refreshed offline CRLs, in a fresh TLS generation. */
    public synchronized TlsSnapshot reloadPeerPolicy(TlsPeerPolicy peerPolicy) {
        return publish(current.get().getIdentity().orElse(null), current.get().getTrustBundle(),
                Objects.requireNonNull(peerPolicy, "peerPolicy"));
    }
    private TlsSnapshot publish(PkiIdentity identity, TrustBundle trust) {
        return publish(identity, trust, policy);
    }
    private TlsSnapshot publish(PkiIdentity identity, TrustBundle trust, TlsPeerPolicy candidatePolicy) {
        long next = Math.addExact(current.get().getGeneration(), 1);
        TlsSnapshot candidate = TlsMaterialSupport.prepare(next, identity, trust, candidatePolicy);
        policy = candidatePolicy;
        current.set(candidate);
        return candidate;
    }
}
