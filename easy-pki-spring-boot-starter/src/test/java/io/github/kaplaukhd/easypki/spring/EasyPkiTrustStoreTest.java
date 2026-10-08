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
package io.github.kaplaukhd.easypki.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class EasyPkiTrustStoreTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final KeyPair KEYS_A = PkiKeys.rsa(2048);
    private static final KeyPair KEYS_B = PkiKeys.rsa(2048);
    private static final X509Certificate ROOT_A = root("A", KEYS_A);
    private static final X509Certificate ROOT_B = root("B", KEYS_B);
    private static final X509Certificate LEAF_A = leaf("A", ROOT_A, KEYS_A);
    private static final X509Certificate LEAF_B = leaf("B", ROOT_B, KEYS_B);

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EasyPkiAutoConfiguration.class))
            .withPropertyValues("easy-pki.validation.mode=NONE");

    @TempDir
    Path temporary;

    @Test
    void allTrustedAliasesReachValidatorMonitorAndHealth() throws Exception {
        KeyStore store = emptyStore();
        // Deliberately add aliases in reverse order: the published snapshot must be stable.
        store.setCertificateEntry("z-root-b", ROOT_B);
        store.setCertificateEntry("a-root-a", ROOT_A);
        Path path = save(store);

        withStore(path).withPropertyValues("easy-pki.monitoring.enabled=true").run(context -> {
            assertThat(context).hasNotFailed();
            Pkcs12Bundle bundle = context.getBean(
                    EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class);
            assertThat(bundle.getCertificate()).isEqualTo(ROOT_A);
            assertThat(bundle.getAlias()).isEqualTo("a-root-a");
            assertThat(bundle.getPrivateKey()).isNull();
            assertThat(bundle.getChain()).containsExactly(ROOT_A, ROOT_B);

            EasyPkiValidator validator = context.getBean(EasyPkiValidator.class);
            assertThat(validator.getTrustAnchors()).containsExactly(ROOT_A, ROOT_B);
            assertThat(validator.validate(LEAF_A).isValid()).isTrue();
            assertThat(validator.validate(LEAF_B).isValid()).isTrue();
            assertThat(context.getBean(CertificateMonitor.class).monitored())
                    .containsExactlyInAnyOrder(ROOT_A, ROOT_B);
            Map<String, Object> details = context.getBean(EasyPkiHealthIndicator.class)
                    .health().getDetails();
            assertThat(details).containsOnlyKeys("easyPkiTrustStore[0]", "easyPkiTrustStore[1]");
        });
    }

    @Test
    void duplicateTrustedEntriesAreDeduplicatedWithoutLosingIndependentRoots() throws Exception {
        KeyStore store = emptyStore();
        store.setCertificateEntry("a-root-a", ROOT_A);
        store.setCertificateEntry("b-root-a-copy", ROOT_A);
        store.setCertificateEntry("z-root-b", ROOT_B);
        withStore(save(store)).run(context -> {
            assertThat(context).hasNotFailed();
            Pkcs12Bundle bundle = context.getBean(
                    EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class);
            assertThat(bundle.getAlias()).isEqualTo("a-root-a");
            assertThat(bundle.getChain()).containsExactly(ROOT_A, ROOT_B);
            EasyPkiValidator validator = context.getBean(EasyPkiValidator.class);
            assertThat(validator.validate(LEAF_A).isValid()).isTrue();
            assertThat(validator.validate(LEAF_B).isValid()).isTrue();
        });
    }

    @Test
    void privateKeyIdentityIntermediatesRemainUntrusted() throws Exception {
        KeyPair intermediateKeys = PkiKeys.rsa(2048);
        X509Certificate intermediate = PkiCertificate.signed()
                .subject("CN=Starter Identity Intermediate").publicKey(intermediateKeys.getPublic())
                .issuer(ROOT_A, KEYS_A.getPrivate()).pathLength(0)
                .validFor(Duration.ofDays(100)).build();
        X509Certificate leaf = leaf("Intermediate", intermediate, intermediateKeys);
        KeyStore store = emptyStore();
        store.setKeyEntry("identity-intermediate", intermediateKeys.getPrivate(), PASSWORD,
                new X509Certificate[]{intermediate, ROOT_A});
        store.setCertificateEntry("trusted-b", ROOT_B);
        withStore(save(store)).run(context -> {
            assertThat(context).hasNotFailed();
            EasyPkiValidator validator = context.getBean(EasyPkiValidator.class);
            assertThat(validator.getTrustAnchors()).containsExactly(ROOT_B);
            assertThat(validator.validate(leaf, intermediate, ROOT_A).isValid()).isFalse();
            assertThat(validator.validate(LEAF_B).isValid()).isTrue();
        });
    }

    @Test
    void privateKeyEntriesNeverBecomeImplicitTrustAnchors() throws Exception {
        KeyStore store = emptyStore();
        store.setKeyEntry("identity-a", KEYS_A.getPrivate(), PASSWORD,
                new X509Certificate[]{ROOT_A});
        store.setCertificateEntry("trusted-b", ROOT_B);

        withStore(save(store)).run(context -> {
            assertThat(context).hasNotFailed();
            EasyPkiValidator validator = context.getBean(EasyPkiValidator.class);
            assertThat(validator.getTrustAnchors()).containsExactly(ROOT_B);
            assertThat(validator.validate(LEAF_B).isValid()).isTrue();
            assertThat(validator.validate(LEAF_A, ROOT_A).isValid()).isFalse();
            assertThat(context.getBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class)
                    .getPrivateKey()).isNull();
        });
    }

    @Test
    void emptyTrustStoreFailsClearly() throws Exception {
        withStore(save(emptyStore())).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseMessage(
                    "PKCS#12 trust store contains no trusted X.509 certificate entries");
        });
    }

    @Test
    void keyOnlyStoreFailsClearlyWhenConfiguredAsTrust() throws Exception {
        KeyStore store = emptyStore();
        store.setKeyEntry("identity-a", KEYS_A.getPrivate(), PASSWORD,
                new X509Certificate[]{ROOT_A});
        withStore(save(store)).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseMessage(
                    "PKCS#12 trust store contains no trusted X.509 certificate entries");
        });
    }

    @Test
    void wrongPasswordStillFailsStartup() throws Exception {
        KeyStore store = emptyStore();
        store.setCertificateEntry("trusted-a", ROOT_A);
        withStore(save(store)).withPropertyValues("easy-pki.trust-store.password=incorrect")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void customNamedTrustBundleWinsAndFeedsAllConsumers() {
        Pkcs12Bundle custom = PkiPkcs12.create().certificate(ROOT_B).chain(ROOT_A)
                .alias("custom").password("").build();

        contextRunner.withBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN,
                        Pkcs12Bundle.class, () -> custom)
                .withPropertyValues("easy-pki.trust-store.path=file:/missing-test-truststore.p12",
                        "easy-pki.monitoring.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN))
                            .isSameAs(custom);
                    assertThat(context.getBean(EasyPkiValidator.class).getTrustAnchors())
                            .containsExactly(ROOT_B, ROOT_A);
                    assertThat(context.getBean(CertificateMonitor.class).monitored())
                            .containsExactlyInAnyOrder(ROOT_A, ROOT_B);
                    assertThat(context.getBean(EasyPkiHealthIndicator.class).health().getDetails())
                            .hasSize(2);
                });
    }

    @Test
    void keyStoreStillLoadsItsPrivateKeyAndChain() throws Exception {
        KeyStore store = emptyStore();
        store.setKeyEntry("identity-a", KEYS_A.getPrivate(), PASSWORD,
                new X509Certificate[]{ROOT_A});
        contextRunner.withPropertyValues("easy-pki.key-store.path=file:" + save(store),
                        "easy-pki.key-store.password=changeit")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    Pkcs12Bundle bundle = context.getBean(
                            EasyPkiAutoConfiguration.KEY_STORE_BEAN, Pkcs12Bundle.class);
                    assertThat(bundle.getCertificate()).isEqualTo(ROOT_A);
                    assertThat(bundle.getPrivateKey()).isEqualTo(KEYS_A.getPrivate());
                    assertThat(bundle.getChain()).isEqualTo(List.of(ROOT_A));
                    assertThat(context.getBean(EasyPkiValidator.class).getTrustAnchors()).isEmpty();
                });
    }

    private ApplicationContextRunner withStore(Path path) {
        return contextRunner.withPropertyValues("easy-pki.trust-store.path=file:" + path,
                "easy-pki.trust-store.password=changeit");
    }

    private Path save(KeyStore store) throws Exception {
        Path path = temporary.resolve("store.p12");
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, PASSWORD);
        }
        return path;
    }

    private static KeyStore emptyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        return store;
    }

    private static X509Certificate root(String name, KeyPair keys) {
        return PkiCertificate.selfSigned().subject("CN=Starter Root " + name)
                .keyPair(keys).isCA(true).validFor(Duration.ofDays(365)).build();
    }

    private static X509Certificate leaf(String name, X509Certificate issuer, KeyPair issuerKeys) {
        return PkiCertificate.signed().subject("CN=Starter Leaf " + name)
                .publicKey(PkiKeys.rsa(2048).getPublic()).issuer(issuer, issuerKeys.getPrivate())
                .validFor(Duration.ofDays(30)).build();
    }
}
