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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.PkiKeys;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.DestroyFailedException;
import org.junit.jupiter.api.Test;

class TlsKeySupportTest {
    @Test
    void knownBcSoftwareKeyUsesANonserializableEdDsaViewThatSignsThroughItsJcaInterface() throws Exception {
        var providers = Security.getProviders();
        KeyPair pair = PkiKeys.ed25519();
        EdECPrivateKey original = (EdECPrivateKey) pair.getPrivate();
        PrivateKey adapted = TlsKeySupport.forJsse(original);
        assertThat(adapted).isNotSameAs(original).isInstanceOf(EdECPrivateKey.class);
        assertThat(original.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(adapted.getAlgorithm()).isEqualTo("EdDSA");
        assertThat(adapted.getFormat()).isNull();
        assertThat(adapted.getEncoded()).isNull();
        EdECPrivateKey view = (EdECPrivateKey) adapted;
        assertThat(view.getParams().getName()).isEqualTo(original.getParams().getName()).isEqualTo("Ed25519");
        assertThat(view.getBytes().orElseThrow()).isEqualTo(original.getBytes().orElseThrow());
        assertThat(TlsKeySupport.forJsse(view)).isSameAs(view);
        assertThatThrownBy(() -> {
            try (var output = new ObjectOutputStream(new ByteArrayOutputStream())) { output.writeObject(view); }
        }).isInstanceOf(NotSerializableException.class);
        assertThatThrownBy(view::destroy).isInstanceOf(DestroyFailedException.class);
        assertThat(original.isDestroyed()).isFalse();
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(view);
        byte[] message = {1, 2, 3};
        signer.update(message);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(pair.getPublic());
        verifier.update(message);
        assertThat(verifier.verify(signature)).isTrue();
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void leavesAllOtherProviderAndOpaqueHandlesUntouchedWithoutAccessingKeyMaterial() throws Exception {
        PrivateKey ec = PkiKeys.ec(Curve.P_256).getPrivate();
        PrivateKey jdkEd = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate();
        assertThat(TlsKeySupport.forJsse(ec)).isSameAs(ec);
        assertThat(TlsKeySupport.forJsse(jdkEd)).isSameAs(jdkEd);
        AtomicInteger exports = new AtomicInteger();
        EdECPrivateKey opaque = new EdECPrivateKey() {
            private static final long serialVersionUID = 1L;
            @Override public String getAlgorithm() { return "Ed25519"; }
            @Override public NamedParameterSpec getParams() { return NamedParameterSpec.ED25519; }
            @Override public Optional<byte[]> getBytes() { exports.incrementAndGet(); throw new AssertionError("Opaque seed"); }
            @Override public String getFormat() { return null; }
            @Override public byte[] getEncoded() { exports.incrementAndGet(); throw new AssertionError("Opaque key"); }
        };
        assertThat(TlsKeySupport.forJsse(opaque)).isSameAs(opaque);
        assertThat(exports).hasValue(0);
        assertThat(TlsKeySupport.forJsse(null)).isNull();
    }
}
