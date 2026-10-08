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
import java.time.Duration;
import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.TrustBundle;
import org.junit.jupiter.api.Test;

class IdentityTrustSeparationTest {
    @Test
    void identityChainDoesNotGrantTrustUntilAnAnchorIsExplicitlyConfigured() {
        var rootKeys = PkiKeys.ed25519();
        var root = PkiCertificate.selfSigned().subject("CN=Explicit Identity Trust")
                .keyPair(rootKeys).isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN)
                .validFor(Duration.ofDays(5)).build();
        var keys = PkiKeys.ec(Curve.P_256);
        var leaf = PkiCertificate.signed().subject("CN=Identity Subject").keyPair(keys)
                .issuer(root, rootKeys.getPrivate()).validFor(Duration.ofDays(1)).build();
        var identity = PkiIdentity.of(leaf, keys.getPrivate(), root);
        var issuerChain = identity.getChain().subList(1, identity.getChain().size());
        var untrusted = CertValidator.of(identity.getCertificate()).chain(issuerChain).validate();
        assertThat(untrusted.isValid()).isFalse();
        assertThat(untrusted.getErrors()).anyMatch(e -> e.code() == ValidationError.Code.UNTRUSTED_ROOT);
        var trusted = CertValidator.of(identity.getCertificate()).chain(issuerChain)
                .trustBundle(TrustBundle.of(root)).validate();
        assertThat(trusted.isValid()).isTrue();
        assertThat(ChainBuilder.of(identity.getCertificate()).trustBundle(TrustBundle.of(root))
                .build().validate().isValid()).isTrue();
    }
}
