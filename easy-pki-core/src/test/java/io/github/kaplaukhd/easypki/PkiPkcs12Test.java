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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    @ParameterizedTest
    @ValueSource(strings = {"trust", "trust-2", "MixedCase", ""})
    void trustOnlyChainRoundTripPreservesEveryCertificate(String alias, @TempDir Path tmp)
            throws Exception {
        Pkcs12Bundle bundle = PkiPkcs12.create()
                .certificate(leaf)
                .chain(root)
                .alias(alias)
                .password("trust-password")
                .build();

        byte[] bytes = bundle.toBytes();
        KeyStore store = readKeyStore(bytes, "trust-password");
        String storedAlias = alias.toLowerCase(Locale.ROOT);
        assertThat(Collections.list(store.aliases()))
                .containsExactlyInAnyOrder(storedAlias, storedAlias + "-2");
        assertThat(store.isCertificateEntry(storedAlias)).isTrue();
        assertThat(store.isCertificateEntry(storedAlias + "-2")).isTrue();
        assertThat(store.getCertificate(storedAlias)).isEqualTo(leaf);
        assertThat(store.getCertificate(storedAlias + "-2")).isEqualTo(root);

        Pkcs12Bundle fromBytes = PkiPkcs12.load(bytes, "trust-password");
        assertThat(fromBytes.getPrivateKey()).isNull();
        assertThat(fromBytes.getAlias()).isEqualTo(storedAlias);
        assertThat(fromBytes.getCertificate()).isEqualTo(leaf);
        assertThat(fromBytes.getChain()).containsExactly(leaf, root);

        Path path = tmp.resolve("trust.p12");
        fromBytes.saveTo(path);
        Pkcs12Bundle fromFile = PkiPkcs12.load(path, "trust-password");
        assertThat(fromFile.getAlias()).isEqualTo(storedAlias);
        assertThat(fromFile.getChain()).containsExactly(leaf, root);
        assertThat(fromFile.getPrivateKey()).isNull();
    }

    @Test
    void externalTrustStoreRetainsAliasesAndLoadsInLexicographicOrder() throws Exception {
        KeyStore external = KeyStore.getInstance("PKCS12");
        external.load(null, null);
        // Insertion order deliberately differs from the documented alias order.
        external.setCertificateEntry("z-last", root);
        external.setCertificateEntry("a-first-2", leaf);
        external.setCertificateEntry("a-first", leaf);
        external.setCertificateEntry("a-first-10", root);

        Pkcs12Bundle loaded = PkiPkcs12.load(storeBytes(external, "p"), "p");

        assertThat(loaded.getAlias()).isEqualTo("a-first");
        assertThat(loaded.getCertificate()).isEqualTo(leaf);
        assertThat(loaded.getPrivateKey()).isNull();
        assertThat(loaded.getChain()).containsExactly(leaf, root, leaf, root);
        KeyStore exported = readKeyStore(loaded.toBytes(), "p");
        assertThat(Collections.list(exported.aliases()))
                .containsExactlyInAnyOrder("a-first", "a-first-2", "a-first-10", "z-last");
        for (String alias : Collections.list(external.aliases())) {
            assertThat(exported.isCertificateEntry(alias)).isTrue();
            assertThat(exported.getCertificate(alias)).isEqualTo(external.getCertificate(alias));
        }
        assertThat(PkiPkcs12.load(loaded.toBytes(), "p").getChain())
                .containsExactlyElementsOf(loaded.getChain());
    }

    @Test
    void trustOnlyRepeatedCertificatesKeepDistinctAliasesBeyondNineEntries() throws Exception {
        List<X509Certificate> extraCertificates = List.of(
                root, root, root, root, root, root, root, root, leaf, root, root);
        Pkcs12Bundle bundle = PkiPkcs12.create()
                .certificate(leaf)
                .chain(extraCertificates)
                .password("p")
                .build();

        KeyStore exported = readKeyStore(bundle.toBytes(), "p");
        assertThat(exported.size()).isEqualTo(12);
        assertThat(exported.getCertificate("1")).isEqualTo(leaf);
        for (int i = 0; i < extraCertificates.size(); i++) {
            assertThat(exported.isCertificateEntry("1-" + (i + 2))).isTrue();
            assertThat(exported.getCertificate("1-" + (i + 2))).isEqualTo(extraCertificates.get(i));
        }
        Pkcs12Bundle loaded = PkiPkcs12.load(bundle.toBytes(), "p");
        assertThat(loaded.getAlias()).isEqualTo("1");
        // "1-10" sorts before "1-2"; trust-only entries do not form a chain.
        assertThat(loaded.getChain()).containsExactly(
                leaf, leaf, root, root, root, root, root, root, root, root, root, root);
        KeyStore reexported = readKeyStore(loaded.toBytes(), "p");
        assertThat(reexported.size()).isEqualTo(12);
        for (String alias : Collections.list(exported.aliases())) {
            assertThat(reexported.getCertificate(alias)).isEqualTo(exported.getCertificate(alias));
        }
    }

    @Test
    void identityStoreStillSelectsKeyEntryAndItsChain() throws Exception {
        KeyStore external = KeyStore.getInstance("PKCS12");
        external.load(null, null);
        external.setCertificateEntry("a-trust", root);
        external.setKeyEntry("server", leafKeys.getPrivate(), "p".toCharArray(),
                new X509Certificate[] {leaf, root});

        Pkcs12Bundle loaded = PkiPkcs12.load(storeBytes(external, "p"), "p");

        assertThat(loaded.getAlias()).isEqualTo("server");
        assertThat(loaded.getPrivateKey().getEncoded()).isEqualTo(leafKeys.getPrivate().getEncoded());
        assertThat(loaded.getChain()).containsExactly(leaf, root);
        KeyStore exported = readKeyStore(loaded.toBytes(), "p");
        assertThat(Collections.list(exported.aliases())).containsExactly("server");
        assertThat(exported.isKeyEntry("server")).isTrue();
        assertThat(exported.getCertificateChain("server")).containsExactly(leaf, root);
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

    private static KeyStore readKeyStore(byte[] bytes, String password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var in = new ByteArrayInputStream(bytes)) {
            store.load(in, password.toCharArray());
        }
        return store;
    }

    private static byte[] storeBytes(KeyStore store, String password) throws Exception {
        try (var out = new ByteArrayOutputStream()) {
            store.store(out, password.toCharArray());
            return out.toByteArray();
        }
    }
}
