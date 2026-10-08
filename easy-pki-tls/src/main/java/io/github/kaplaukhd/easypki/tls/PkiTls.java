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

/** Creates JSSE contexts with explicit peer trust and an explicit revocation choice. */
public final class PkiTls {
    private PkiTls() {}

    /** Starts TLS configuration. Identity is optional for clients; trust and peer policy are required. */
    public static Builder builder() { return new Builder(); }

    /** Mutable configuration builder; the resulting context owns immutable material generations. */
    public static final class Builder {
        private PkiIdentity identity;
        private TrustBundle trust;
        private TlsPeerPolicy policy;
        private Builder() {}

        /** Sets a local identity with a JCA PrivateKey handle usable by the installed JSSE/JCA providers. */
        public Builder identity(PkiIdentity value) { identity = Objects.requireNonNull(value, "identity"); return this; }

        /** Sets explicit peer anchors. An empty bundle rejects every certificate; system roots are never implicit. */
        public Builder trust(TrustBundle value) { trust = Objects.requireNonNull(value, "trust"); return this; }

        /** Selects peer validation, including an explicit revocation policy. */
        public Builder peerPolicy(TlsPeerPolicy value) { policy = Objects.requireNonNull(value, "peerPolicy"); return this; }

        /** Validates material and creates generation zero without changing global JSSE defaults. */
        public ReloadableTlsContext build() {
            if (trust == null || policy == null) throw new IllegalStateException("TLS requires explicit trust and peerPolicy");
            return new ReloadableTlsContext(identity, trust, policy);
        }
    }
}
