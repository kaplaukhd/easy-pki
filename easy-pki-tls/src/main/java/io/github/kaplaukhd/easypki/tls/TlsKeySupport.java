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

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;

/** Local compatibility views; never converts or serializes a caller's private key. */
final class TlsKeySupport {
    private TlsKeySupport() {}

    static PrivateKey forJsse(PrivateKey key) {
        // BC's Java 15+ key implements EdECPrivateKey but reports Ed25519.
        // SunJSSE compares this label with its EdDSA certificate public key
        // before asking SunEC to sign through the standard EdEC interface.
        if (key instanceof BCEdDSAPrivateKey && key instanceof EdECPrivateKey ed
                && "Ed25519".equals(key.getAlgorithm())
                && "Ed25519".equals(ed.getParams().getName())) {
            return new Ed25519View(ed);
        }
        // In particular, opaque/provider-specific handles retain their exact identity.
        return key;
    }

    private static final class Ed25519View implements EdECPrivateKey {
        private static final long serialVersionUID = 1L;
        private final EdECPrivateKey key;
        private Ed25519View(EdECPrivateKey key) { this.key = key; }
        @Override public String getAlgorithm() { return "EdDSA"; }
        @Override public NamedParameterSpec getParams() { return key.getParams(); }
        // The signing provider accesses the existing software key through its JCA interface.
        // Creating the view does not read the seed or an encoded private key.
        @Override public Optional<byte[]> getBytes() { return key.getBytes(); }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
        // The view does not acquire ownership of, or delegate destruction to, the caller's key.
        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("TLS Ed25519 key views cannot be serialized");
        }
    }
}
