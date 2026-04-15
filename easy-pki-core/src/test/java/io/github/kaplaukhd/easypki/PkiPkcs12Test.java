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
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PkiPkcs12Test {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair leafKeys;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Test Root")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();

        leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();
    }

    @Test
    void buildAndSaveAndLoadPreservesLeafKeyAndChain(@TempDir Path tmp) throws Exception {
        Path path = tmp.resolve("keystore.p12");

        Pkcs12Bundle saved = PkiPkcs12.create()
                .certificate(leaf)
                .privateKey(leafKeys.getPrivate())
                .chain(root)
                .alias("server")
                .password("changeit")
                .build();
        saved.saveTo(path);

        Pkcs12Bundle loaded = PkiPkcs12.load(path, "changeit");

        assertThat(loaded.getAlias()).isEqualTo("server");
        assertThat(loaded.getCertificate().getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(loaded.getPrivateKey().getEncoded())
                .isEqualTo(leafKeys.getPrivate().getEncoded());
        assertThat(loaded.getChain()).hasSize(2);
        assertThat(loaded.getChain().get(0).getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(loaded.getChain().get(1).getEncoded()).isEqualTo(root.getEncoded());
    }

    @Test
    void byteArrayRoundTrip() throws Exception {
        Pkcs12Bundle saved = PkiPkcs12.create()
                .certificate(leaf)
                .privateKey(leafKeys.getPrivate())
                .chain(root)
                .password("secret")
                .build();

        byte[] bytes = saved.toBytes();
        Pkcs12Bundle loaded = PkiPkcs12.load(bytes, "secret");

        assertThat(loaded.getCertificate().getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(loaded.getChain()).hasSize(2);
    }

    @Test
    void wrongPasswordOnLoadThrowsIllegalArgument() throws Exception {
        byte[] bytes = PkiPkcs12.create()
                .certificate(leaf)
                .privateKey(leafKeys.getPrivate())
                .password("right")
                .build()
                .toBytes();

        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiPkcs12.load(bytes, "wrong"))
                .withMessageContaining("password");
    }

    @Test
    void trustOnlyBundleHasNoPrivateKey() throws Exception {
        Pkcs12Bundle bundle = PkiPkcs12.create()
                .certificate(root)
                .alias("trust-root")
                .password("t")
                .build();

        byte[] bytes = bundle.toBytes();
        Pkcs12Bundle loaded = PkiPkcs12.load(bytes, "t");

        assertThat(loaded.getPrivateKey()).isNull();
        assertThat(loaded.getCertificate().getEncoded()).isEqualTo(root.getEncoded());
    }

    @Test
    void missingCertificateRejected() {
        assertThatIllegalStateException()
                .isThrownBy(() -> PkiPkcs12.create().password("p").build())
                .withMessageContaining("certificate");
    }

    @Test
    void missingPasswordRejected() {
        assertThatIllegalStateException()
                .isThrownBy(() -> PkiPkcs12.create().certificate(leaf).build())
                .withMessageContaining("password");
    }

    @Test
    void outputIsReadableByStandardJcaKeyStore(@TempDir Path tmp) throws Exception {
        Path path = tmp.resolve("ks.p12");

        PkiPkcs12.create()
                .certificate(leaf)
                .privateKey(leafKeys.getPrivate())
                .chain(root)
                .alias("server")
                .password("changeit")
                .build()
                .saveTo(path);

        // Independently parse via standard JCA to verify interop.
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var in = java.nio.file.Files.newInputStream(path)) {
            ks.load(in, "changeit".toCharArray());
        }

        assertThat(ks.containsAlias("server")).isTrue();
        assertThat(ks.isKeyEntry("server")).isTrue();
        assertThat(ks.getCertificateChain("server")).hasSize(2);
    }

    @Test
    void chainListOverloadWorksLikeVarargs() throws Exception {
        Pkcs12Bundle bundle = PkiPkcs12.create()
                .certificate(leaf)
                .privateKey(leafKeys.getPrivate())
                .chain(java.util.List.of(root))
                .password("p")
                .build();

        Pkcs12Bundle loaded = PkiPkcs12.load(bundle.toBytes(), "p");
        assertThat(loaded.getChain()).hasSize(2);
    }
}
