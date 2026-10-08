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
package io.github.kaplaukhd.easypki.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiCertificates;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.TrustBundle;
import org.junit.jupiter.api.Test;

class TrustBundleValidationTest {

    private static final KeyPair ROOT_KEYS_A = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ROOT_KEYS_B = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT_A = root("A", ROOT_KEYS_A);
    private static final X509Certificate ROOT_B = root("B", ROOT_KEYS_B);
    private static final KeyPair INTERMEDIATE_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate INTERMEDIATE = PkiCertificate.signed()
            .subject("CN=Bundle Intermediate").publicKey(INTERMEDIATE_KEYS.getPublic())
            .issuer(ROOT_A, ROOT_KEYS_A.getPrivate()).pathLength(0)
            .validFor(Duration.ofDays(180)).build();
    private static final X509Certificate LEAF_A = leaf("A", INTERMEDIATE, INTERMEDIATE_KEYS);
    private static final X509Certificate LEAF_B = leaf("B", ROOT_B, ROOT_KEYS_B);

    @Test
    void mergedIndependentRootsValidateAndBuildBothPaths() {
        TrustBundle anchors = TrustBundle.fromPem(PkiCertificates.toPem(ROOT_B))
                .merge(TrustBundle.of(ROOT_A), TrustBundle.of(ROOT_B));
        assertThat(CertValidator.of(LEAF_A).chain(INTERMEDIATE).trustBundle(anchors)
                .validate().isValid()).isTrue();
        assertThat(CertValidator.of(LEAF_B).trustBundle(anchors).validate().isValid()).isTrue();
        assertThat(ChainBuilder.of(LEAF_A).intermediates(INTERMEDIATE).trustBundle(anchors)
                .build().getCertificates()).containsExactly(LEAF_A, INTERMEDIATE, ROOT_A);
        assertThat(ChainBuilder.of(LEAF_B).trustBundle(anchors).build().getCertificates())
                .containsExactly(LEAF_B, ROOT_B);
    }

    @Test
    void legacyAnchorsAndBundleCallsAccumulate() {
        CertValidator validator = CertValidator.of(LEAF_B).trustAnchors(ROOT_A)
                .trustBundle(TrustBundle.of(ROOT_B)).trustBundle(TrustBundle.of());
        assertThat(validator.validate().isValid()).isTrue();
        assertThat(ChainBuilder.of(LEAF_A).intermediates(INTERMEDIATE)
                .trustBundle(TrustBundle.of(ROOT_A)).trustAnchors(ROOT_B)
                .trustBundle(TrustBundle.of()).build().getRoot()).isEqualTo(ROOT_A);
    }

    @Test
    void explicitIntermediateAndTargetRetainTheirExistingTrustMeaning() {
        TrustBundle trustedIntermediate = TrustBundle.fromPem(PkiCertificates.toPem(INTERMEDIATE));
        assertThat(CertValidator.of(LEAF_A).trustBundle(trustedIntermediate).validate().isValid()).isTrue();
        assertThat(ChainBuilder.of(LEAF_A).trustBundle(trustedIntermediate).build().getCertificates())
                .containsExactly(LEAF_A, INTERMEDIATE);
        assertThat(CertValidator.of(LEAF_A).trustBundle(TrustBundle.of(LEAF_A)).validate().isValid()).isTrue();
        assertThat(ChainBuilder.of(LEAF_A).trustBundle(TrustBundle.of(LEAF_A)).build().getCertificates())
                .containsExactly(LEAF_A);
    }

    @Test
    void emptyBundleNeverPromotesPeerChainToTrust() {
        ValidationResult result = CertValidator.of(LEAF_A).chain(INTERMEDIATE, ROOT_A)
                .trustBundle(TrustBundle.of()).validate();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).extracting(ValidationError::code)
                .contains(ValidationError.Code.UNTRUSTED_ROOT);
        assertThatIllegalStateException().isThrownBy(() -> ChainBuilder.of(LEAF_A)
                .intermediates(INTERMEDIATE, ROOT_A).trustBundle(TrustBundle.of()).build())
                .withMessageContaining("At least one trust anchor");
    }

    @Test
    void keyStoreIdentityChainNeverBecomesTrust() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("identity", INTERMEDIATE_KEYS.getPrivate(), "secret".toCharArray(),
                new X509Certificate[]{INTERMEDIATE, ROOT_A});
        store.setCertificateEntry("trusted-b", ROOT_B);
        TrustBundle anchors = TrustBundle.fromKeyStore(store);
        assertThat(CertValidator.of(LEAF_A).chain(INTERMEDIATE, ROOT_A).trustBundle(anchors)
                .validate().isValid()).isFalse();
        assertThat(CertValidator.of(LEAF_B).trustBundle(anchors).validate().isValid()).isTrue();
        assertThatIllegalStateException().isThrownBy(() -> ChainBuilder.of(LEAF_A)
                .intermediates(INTERMEDIATE, ROOT_A).trustStore(store).build())
                .withMessageContaining("Unable to build a valid certificate path");
        assertThat(ChainBuilder.of(LEAF_B).trustStore(store).build().getRoot()).isEqualTo(ROOT_B);
    }

    @Test
    void bundleArgumentsRejectNull() {
        assertThatNullPointerException().isThrownBy(() -> CertValidator.of(LEAF_A).trustBundle(null));
        assertThatNullPointerException().isThrownBy(() -> ChainBuilder.of(LEAF_A).trustBundle(null));
    }

    private static X509Certificate root(String name, KeyPair keys) {
        return PkiCertificate.selfSigned().subject("CN=Bundle Root " + name)
                .keyPair(keys).isCA(true).validFor(Duration.ofDays(365)).build();
    }

    private static X509Certificate leaf(String name, X509Certificate issuer, KeyPair keys) {
        return PkiCertificate.signed().subject("CN=Bundle Leaf " + name)
                .publicKey(PkiKeys.ec(Curve.P_256).getPublic()).issuer(issuer, keys.getPrivate())
                .validFor(Duration.ofDays(30)).build();
    }
}
