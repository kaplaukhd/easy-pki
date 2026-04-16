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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;

import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class EasyPkiAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EasyPkiAutoConfiguration.class));

    @TempDir
    Path tmp;

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair leafKeys;
    private X509Certificate leaf;
    private Path trustStoreFile;

    @BeforeEach
    void setUp() throws Exception {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Test Starter Root")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(3650))
                .isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();
        leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .build();

        // Trust store with just the root as a certificate entry.
        byte[] bundle = PkiPkcs12.create()
                .certificate(root)
                .alias("root")
                .password("changeit")
                .build()
                .toBytes();
        trustStoreFile = tmp.resolve("truststore.p12");
        Files.write(trustStoreFile, bundle);
    }

    @Test
    void propertiesAreBoundWithDefaults() {
        contextRunner.run(ctx -> {
            EasyPkiProperties props = ctx.getBean(EasyPkiProperties.class);
            assertThat(props.validation().mode()).isEqualTo(ValidationMode.OCSP_WITH_CRL_FALLBACK);
            assertThat(props.validation().ocspTimeout()).isEqualTo(Duration.ofSeconds(5));
            assertThat(props.validation().crlCacheTtl()).isEqualTo(Duration.ofMinutes(30));
            assertThat(props.validation().httpTimeout()).isEqualTo(Duration.ofSeconds(10));
            assertThat(props.monitoring().enabled()).isFalse();
        });
    }

    @Test
    void trustStoreIsLoadedWhenPathIsProvided() {
        contextRunner
                .withPropertyValues(
                        "easy-pki.trust-store.path=file:" + trustStoreFile.toAbsolutePath(),
                        "easy-pki.trust-store.password=changeit")
                .run(ctx -> {
                    assertThat(ctx).hasBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN);
                    Pkcs12Bundle store = ctx.getBean(
                            EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class);
                    assertThat(store.getCertificate().getEncoded()).isEqualTo(root.getEncoded());
                });
    }

    @Test
    void trustStoreBeanAbsentWhenPathNotConfigured() {
        contextRunner.run(ctx ->
                assertThat(ctx).doesNotHaveBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN));
    }

    @Test
    void validatorIsExposedAndUsesTrustStoreAnchors() {
        contextRunner
                .withPropertyValues(
                        "easy-pki.trust-store.path=file:" + trustStoreFile.toAbsolutePath(),
                        "easy-pki.trust-store.password=changeit",
                        "easy-pki.validation.mode=NONE")
                .run(ctx -> {
                    EasyPkiValidator validator = ctx.getBean(EasyPkiValidator.class);
                    assertThat(validator.getTrustAnchors())
                            .extracting(X509Certificate::getEncoded)
                            .containsExactly(root.getEncoded());

                    ValidationResult result = validator.validate(leaf, root);
                    assertThat(result.isValid()).isTrue();
                    assertThat(result.isTrusted()).isTrue();
                });
    }

    @Test
    void validatorHasNoAnchorsWhenNoTrustStore() {
        contextRunner
                .withPropertyValues("easy-pki.validation.mode=NONE")
                .run(ctx -> {
                    EasyPkiValidator validator = ctx.getBean(EasyPkiValidator.class);
                    assertThat(validator.getTrustAnchors()).isEmpty();
                });
    }

    @Test
    void modeProperyIsBound() {
        contextRunner
                .withPropertyValues(
                        "easy-pki.validation.mode=CRL",
                        "easy-pki.validation.crl-cache-ttl=15m",
                        "easy-pki.validation.proxy=http://proxy.corp:3128")
                .run(ctx -> {
                    EasyPkiProperties props = ctx.getBean(EasyPkiProperties.class);
                    assertThat(props.validation().mode()).isEqualTo(ValidationMode.CRL);
                    assertThat(props.validation().crlCacheTtl()).isEqualTo(Duration.ofMinutes(15));
                    assertThat(props.validation().proxy()).isEqualTo("http://proxy.corp:3128");

                    EasyPkiValidator validator = ctx.getBean(EasyPkiValidator.class);
                    assertThat(validator.getMode()).isEqualTo(ValidationMode.CRL);
                });
    }

    @Test
    void monitorBeanAbsentByDefault() {
        contextRunner.run(ctx ->
                assertThat(ctx).doesNotHaveBean(CertificateMonitor.class));
    }

    @Test
    void monitorBeanCreatedWhenEnabledAndRegistersTrustStore() {
        contextRunner
                .withPropertyValues(
                        "easy-pki.monitoring.enabled=true",
                        "easy-pki.monitoring.check-interval=12h",
                        "easy-pki.monitoring.warn-before=30d",
                        "easy-pki.trust-store.path=file:" + trustStoreFile.toAbsolutePath(),
                        "easy-pki.trust-store.password=changeit")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(CertificateMonitor.class);
                    CertificateMonitor monitor = ctx.getBean(CertificateMonitor.class);
                    // The root from the trust store should be registered.
                    assertThat(monitor.monitored())
                            .extracting(X509Certificate::getEncoded)
                            .contains(root.getEncoded());
                });
    }

    @Test
    void userCanOverrideValidator() {
        EasyPkiValidator override = new EasyPkiValidator(
                java.util.List.of(), ValidationMode.NONE,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), null);

        contextRunner
                .withBean(EasyPkiValidator.class, () -> override)
                .run(ctx -> {
                    EasyPkiValidator v = ctx.getBean(EasyPkiValidator.class);
                    assertThat(v).isSameAs(override);
                });
    }
}
