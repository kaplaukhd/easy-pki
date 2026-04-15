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
package io.github.kaplaukhd.easypki;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PkiPrivateKeysTest {

    @Test
    void rsaUnencryptedPemRoundTrip() {
        KeyPair keys = PkiKeys.rsa(2048);
        String pem = PkiPrivateKeys.toPem(keys.getPrivate());

        assertThat(pem).startsWith("-----BEGIN PRIVATE KEY-----");

        PrivateKey restored = PkiPrivateKeys.fromPem(pem);
        assertThat(restored.getEncoded()).isEqualTo(keys.getPrivate().getEncoded());
        assertThat(restored.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void ecUnencryptedPemRoundTrip() {
        KeyPair keys = PkiKeys.ec(Curve.P_256);
        String pem = PkiPrivateKeys.toPem(keys.getPrivate());

        PrivateKey restored = PkiPrivateKeys.fromPem(pem);
        assertThat(restored.getEncoded()).isEqualTo(keys.getPrivate().getEncoded());
        assertThat(restored.getAlgorithm()).isEqualTo("EC");
    }

    @Test
    void encryptedPemRoundTrip() {
        KeyPair keys = PkiKeys.rsa(2048);
        String password = "correct-horse-battery-staple";

        String pem = PkiPrivateKeys.toPem(keys.getPrivate(), password);
        assertThat(pem).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");

        PrivateKey restored = PkiPrivateKeys.fromPem(pem, password);
        assertThat(restored.getEncoded()).isEqualTo(keys.getPrivate().getEncoded());
    }

    @Test
    void encryptedPemRejectsWrongPassword() {
        KeyPair keys = PkiKeys.rsa(2048);
        String pem = PkiPrivateKeys.toPem(keys.getPrivate(), "right");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiPrivateKeys.fromPem(pem, "wrong"))
                .withMessageContaining("decrypt");
    }

    @Test
    void encryptedPemRejectsMissingPassword() {
        KeyPair keys = PkiKeys.rsa(2048);
        String pem = PkiPrivateKeys.toPem(keys.getPrivate(), "secret");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiPrivateKeys.fromPem(pem))
                .withMessageContaining("encrypted");
    }

    @Test
    void fileRoundTripUnencrypted(@TempDir Path tmp) {
        KeyPair keys = PkiKeys.rsa(2048);
        Path path = tmp.resolve("key.pem");

        PkiPrivateKeys.toFile(keys.getPrivate(), path);
        PrivateKey restored = PkiPrivateKeys.fromFile(path);

        assertThat(restored.getEncoded()).isEqualTo(keys.getPrivate().getEncoded());
    }

    @Test
    void fileRoundTripEncrypted(@TempDir Path tmp) {
        KeyPair keys = PkiKeys.ec(Curve.P_384);
        Path path = tmp.resolve("key.pem");
        String password = "secret";

        PkiPrivateKeys.toFile(keys.getPrivate(), path, password);
        PrivateKey restored = PkiPrivateKeys.fromFile(path, password);

        assertThat(restored.getEncoded()).isEqualTo(keys.getPrivate().getEncoded());
    }

    @Test
    void emptyPemRejected() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiPrivateKeys.fromPem(""))
                .withMessageContaining("No PEM");
    }

    @Test
    void certificatePemIsNotAKey() {
        KeyPair keys = PkiKeys.rsa(2048);
        X509Test root = new X509Test(keys);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiPrivateKeys.fromPem(root.pem()));
    }

    /** Tiny helper to produce a certificate PEM for negative test. */
    private static final class X509Test {
        private final String pem;

        X509Test(KeyPair keys) {
            var cert = PkiCertificate.selfSigned()
                    .subject("CN=test")
                    .keyPair(keys)
                    .validFor(java.time.Duration.ofDays(1))
                    .build();
            this.pem = PkiCertificates.toPem(cert);
        }

        String pem() {
            return pem;
        }
    }
}
