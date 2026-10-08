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

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPkcs12;
import io.github.kaplaukhd.easypki.Pkcs12Bundle;
import io.github.kaplaukhd.easypki.TrustBundle;
import io.github.kaplaukhd.easypki.tls.PkiTls;
import io.github.kaplaukhd.easypki.tls.ReloadableTlsContext;
import io.github.kaplaukhd.easypki.tls.TlsPeerPolicy;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.autoconfigure.ssl.SslBundleRegistrar;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class EasyPkiSslAutoConfigurationTest {
    private static final KeyPair CA_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate CA = PkiCertificate.rootCa().subject("CN=SSL Config CA")
            .keyPair(CA_KEYS).validFor(Duration.ofDays(365)).build();
    private static final PkiIdentity CA_IDENTITY = PkiIdentity.of(CA, CA_KEYS.getPrivate());
    private static final KeyPair KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate LEAF = PkiCertificate.tlsClient().subject("CN=SSL Config Client")
            .keyPair(KEYS).issuer(CA_IDENTITY).validFor(Duration.ofDays(30)).build();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EasyPkiAutoConfiguration.class,
                    EasyPkiSslAutoConfiguration.class, SslAutoConfiguration.class));

    @Test
    void existingStoresAndValidatorSettingsDoNotEnableTls() {
        withStores().withPropertyValues("easy-pki.validation.mode=NONE").run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(ReloadableTlsContext.class)
                    .doesNotHaveBean(EasyPkiSslBundle.class);
            assertThat(context).hasSingleBean(SslBundles.class);
        });
    }

    @Test
    void optInRegistersBundleFromExistingNamedStores() {
        withStores().withPropertyValues("easy-pki.ssl.bundle-name=application", "easy-pki.ssl.revocation-mode=disabled")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(ReloadableTlsContext.class);
                    var material = context.getBean(ReloadableTlsContext.class);
                    var bundle = context.getBean(SslBundles.class).getBundle("application");
                    assertThat(bundle.createSslContext()).isSameAs(material.getSslContext());
                    assertThat(material.getSnapshot().getIdentity()).isPresent();
                    assertThat(material.getSnapshot().getTrustBundle().getTrustAnchors()).containsExactly(CA);
                    assertThat(bundle.getStores().getKeyStore()).isSameAs(material.getSnapshot().getKeyStore());
                    assertThat(bundle.getManagers().getTrustManagerFactory().getTrustManagers()).hasSize(1);
                });
    }

    @Test
    void legacyRevocationModeDoesNotSilentlyChooseTlsPeerPolicy() {
        withStores().withPropertyValues("easy-pki.ssl.bundle-name=application", "easy-pki.validation.mode=NONE")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseMessage(
                            "SSL requires an explicit TlsPeerPolicy bean or easy-pki.ssl.revocation-mode=disabled");
                });
    }

    @Test
    void explicitPolicyBeanIsUsedWithoutDisabledProperty() {
        withStores().withBean(TlsPeerPolicy.class, TlsPeerPolicy::withoutRevocationChecks)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void conflictingPolicySourcesAreRejected() {
        withStores().withBean(TlsPeerPolicy.class, TlsPeerPolicy::withoutRevocationChecks)
                .withPropertyValues("easy-pki.ssl.bundle-name=application", "easy-pki.ssl.revocation-mode=disabled")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseMessage(
                            "Choose a TlsPeerPolicy bean or easy-pki.ssl.revocation-mode, not both");
                });
    }

    @Test
    void identityChainDoesNotSupplyMissingTrust() {
        runner.withBean(EasyPkiAutoConfiguration.KEY_STORE_BEAN, Pkcs12Bundle.class, this::keyBundle)
                .withPropertyValues("easy-pki.ssl.bundle-name=application", "easy-pki.ssl.revocation-mode=disabled")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseMessage(
                            "SSL bundle requires an explicit easyPkiTrustStore or an application ReloadableTlsContext");
                });
    }

    @Test
    void customTrustBeanCannotSmuggleAnIdentityChainIntoTlsTrust() {
        runner.withBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class, this::keyBundle)
                .withPropertyValues("easy-pki.ssl.bundle-name=application", "easy-pki.ssl.revocation-mode=disabled")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseMessage(
                            "SSL trust store must contain explicit trusted certificates, not an identity chain");
                });
    }

    @Test
    void applicationTlsContextOwnsItsTrustAndPeerPolicy() {
        ReloadableTlsContext supplied = context();
        runner.withBean(ReloadableTlsContext.class, () -> supplied)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(ReloadableTlsContext.class);
                    assertThat(context.getBean(SslBundles.class).getBundle("application").createSslContext())
                            .isSameAs(supplied.getSslContext());
                });
    }

    @Test
    void customAdapterDoesNotCreateAnotherTlsContext() {
        EasyPkiSslBundle supplied = EasyPkiSslBundle.of(context());
        runner.withBean(EasyPkiSslBundle.class, () -> supplied)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context -> {
                    assertThat(context).hasNotFailed().doesNotHaveBean(ReloadableTlsContext.class);
                    assertThat(context.getBean(SslBundles.class).getBundle("application")).isSameAs(supplied);
                });
    }

    @Test
    void applicationSslBundlesSuppressesAutomaticRegistrationAndStoreRequirements() {
        DefaultSslBundleRegistry supplied = new DefaultSslBundleRegistry();
        runner.withBean(SslBundles.class, () -> supplied)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context -> {
                    assertThat(context).hasNotFailed().doesNotHaveBean(EasyPkiSslBundle.class)
                            .doesNotHaveBean(ReloadableTlsContext.class);
                    assertThat(context.getBean(SslBundles.class)).isSameAs(supplied);
                });
    }

    @Test
    void applicationRegistrySuppressesAutomaticRegistration() {
        runner.withBean(SslBundleRegistry.class, DefaultSslBundleRegistry::new)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context ->
                        assertThat(context).hasNotFailed().doesNotHaveBean(EasyPkiSslBundle.class));
    }

    @Test
    void collisionsWithOtherRegistrarsFailInsteadOfReplacingMaterial() {
        runner.withBean(ReloadableTlsContext.class, EasyPkiSslAutoConfigurationTest::context)
                .withBean("existing", SslBundleRegistrar.class,
                        () -> registry -> registry.registerBundle("application", EasyPkiSslBundle.of(context())))
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseMessage("Cannot replace existing SSL bundle 'application'");
                });
    }

    @Test
    void noTomcatOrServletDependencyIsRequiredForClientBundle() {
        runner.withClassLoader(new FilteredClassLoader("org.apache.tomcat", "org.apache.catalina", "org.apache.coyote", "jakarta.servlet"))
                .withBean(ReloadableTlsContext.class, EasyPkiSslAutoConfigurationTest::context)
                .withPropertyValues("easy-pki.ssl.bundle-name=application").run(context ->
                        assertThat(context).hasNotFailed().hasSingleBean(EasyPkiSslBundle.class));
    }

    private ApplicationContextRunner withStores() {
        return runner.withBean(EasyPkiAutoConfiguration.TRUST_STORE_BEAN, Pkcs12Bundle.class,
                        () -> PkiPkcs12.create().certificate(CA).password("").build())
                .withBean(EasyPkiAutoConfiguration.KEY_STORE_BEAN, Pkcs12Bundle.class, this::keyBundle);
    }

    private Pkcs12Bundle keyBundle() {
        return PkiPkcs12.create().certificate(LEAF).privateKey(KEYS.getPrivate()).chain(CA).password("").build();
    }

    private static ReloadableTlsContext context() {
        return PkiTls.builder().trust(TrustBundle.of(CA)).peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build();
    }
}
