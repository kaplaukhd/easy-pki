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
package io.github.kaplaukhd.easypki.test;

import static org.assertj.core.api.Assertions.assertThat;
import java.security.KeyPair;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiPrivateKeys;
import io.github.kaplaukhd.easypki.validation.CertValidator;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Ed25519OcspTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void ed25519IssuerServesGoodAndRevokedOcspWithNonce(boolean reloaded) {
        KeyPair original = PkiKeys.ed25519();
        KeyPair keys = reloaded ? new KeyPair(original.getPublic(),
                PkiPrivateKeys.fromPem(PkiPrivateKeys.toPem(original.getPrivate()))) : original;
        TestPki pki = TestPki.create().withRootKeys(keys).build();
        try (TestOcspResponder responder = pki.startOcspResponder()) {
            var leaf = pki.issueCert().subject("CN=Ed25519 OCSP issuer")
                    .ocsp(responder.getUrl()).build();
            var good = CertValidator.of(leaf).trustAnchors(pki.getTrustAnchors()).ocsp().validate();
            assertThat(good.isValid()).as("%s", good.getErrors()).isTrue();
            pki.revoke(leaf, RevocationReason.KEY_COMPROMISE);
            var revoked = CertValidator.of(leaf).trustAnchors(pki.getTrustAnchors()).ocsp().validate();
            assertThat(revoked.isValid()).isFalse();
            assertThat(revoked.isRevoked()).isTrue();
            assertThat(revoked.getRevokeReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        }
    }
}
