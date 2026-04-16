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

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(EasyPkiExtension.class)
class EasyPkiExtensionTest {

    @InjectTestPki
    TestPki pki;

    private static TestPki firstRun;

    @Test
    void fieldInjectionProducesReadyPki() {
        assertThat(pki).isNotNull();
        assertThat(pki.hasIntermediate()).isTrue();

        X509Certificate leaf = pki.issueCert().subject("CN=field").build();
        assertThat(leaf.getIssuerX500Principal())
                .isEqualTo(pki.getIntermediateCa().getSubjectX500Principal());
    }

    @Test
    void parameterInjectionProducesReadyPki(@InjectTestPki TestPki injected) {
        assertThat(injected).isNotNull();
        assertThat(injected.hasIntermediate()).isTrue();
        // Parameter-injected instance is independent from the field-injected one.
        assertThat(injected).isNotSameAs(pki);
    }

    @Test
    void withoutIntermediateParameter(
            @InjectTestPki(withIntermediate = false) TestPki root) {
        assertThat(root.hasIntermediate()).isFalse();
        assertThat(root.getIssuerCa()).isEqualTo(root.getRootCa());
    }

    @Test
    void customSubjectsHonoured(
            @InjectTestPki(
                    rootSubject = "CN=Custom Root, O=Acme",
                    intermediateSubject = "CN=Custom Issuer, O=Acme")
            TestPki custom) {
        assertThat(custom.getRootCa().getSubjectX500Principal().getName())
                .contains("CN=Custom Root");
        assertThat(custom.getIntermediateCa().getSubjectX500Principal().getName())
                .contains("CN=Custom Issuer");
    }

    @Test
    void firstOfTwoTests() {
        firstRun = pki;
    }

    @Test
    void secondOfTwoTestsGetsFreshPki() {
        // The extension re-builds the PKI per test method, so the instance
        // differs from the one stashed by firstOfTwoTests().
        assertThat(pki).isNotNull();
        if (firstRun != null) {
            assertThat(pki).isNotSameAs(firstRun);
        }
    }

    @Nested
    @ExtendWith(EasyPkiExtension.class)
    class NestedTests {
        @InjectTestPki
        TestPki nestedPki;

        @Test
        void nestedFieldIsInjected() {
            assertThat(nestedPki).isNotNull();
        }
    }
}
