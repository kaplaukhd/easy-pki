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

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ChainBuilderTest {

    private KeyPair rootKeys;
    private X509Certificate root;
    private KeyPair intermediateKeys;
    private X509Certificate intermediate;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() {
        rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Chain Root")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(3650))
                .isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        intermediateKeys = PkiKeys.rsa(2048);
        intermediate = PkiCertificate.signed()
                .subject("CN=Chain Intermediate")
                .publicKey(intermediateKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825))
                .pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        KeyPair leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .build();
    }

    @Test
    void buildsThreeCertChainFromPool() {
        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(intermediate)
                .trustAnchors(root)
                .build();

        assertThat(chain.size()).isEqualTo(3);
        assertThat(chain.getCertificates()).containsExactly(leaf, intermediate, root);
        assertThat(chain.getLeaf()).isEqualTo(leaf);
        assertThat(chain.getRoot()).isEqualTo(root);
    }

    @Test
    void leafDirectlyUnderRoot_noIntermediateNeeded() {
        // A leaf issued directly by a root, no intermediate.
        KeyPair directLeafKeys = PkiKeys.rsa(2048);
        X509Certificate directLeaf = PkiCertificate.signed()
                .subject("CN=direct-leaf")
                .publicKey(directLeafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        CertChain chain = ChainBuilder.of(directLeaf)
                .trustAnchors(root)
                .build();

        assertThat(chain.size()).isEqualTo(2);
        assertThat(chain.getCertificates()).containsExactly(directLeaf, root);
    }

    @Test
    void ignoresIrrelevantIntermediates() {
        // Put a bunch of unrelated certificates into the pool. Only the real
        // intermediate should be chosen.
        KeyPair otherKeys = PkiKeys.rsa(2048);
        X509Certificate otherRoot = PkiCertificate.selfSigned()
                .subject("CN=Unrelated Root").keyPair(otherKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        KeyPair otherInterKeys = PkiKeys.rsa(2048);
        X509Certificate otherInter = PkiCertificate.signed()
                .subject("CN=Unrelated Inter")
                .publicKey(otherInterKeys.getPublic())
                .issuer(otherRoot, otherKeys.getPrivate())
                .validFor(Duration.ofDays(100)).pathLength(0).build();

        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(otherInter, intermediate, otherRoot) // noise + real
                .trustAnchors(root)
                .build();

        assertThat(chain.getCertificates()).containsExactly(leaf, intermediate, root);
    }

    @Test
    void missingIssuerInPoolThrows() {
        assertThatIllegalStateException()
                .isThrownBy(() -> ChainBuilder.of(leaf)
                        // no intermediate provided
                        .trustAnchors(root)
                        .build())
                .withMessageContaining("no issuer found");
    }

    @Test
    void missingTrustAnchorsThrows() {
        assertThatIllegalStateException()
                .isThrownBy(() -> ChainBuilder.of(leaf)
                        .intermediates(intermediate)
                        .build())
                .withMessageContaining("trust anchor");
    }

    @Test
    void unrelatedRootInTrustStoreCannotComplete() {
        KeyPair otherKeys = PkiKeys.rsa(2048);
        X509Certificate otherRoot = PkiCertificate.selfSigned()
                .subject("CN=Rogue").keyPair(otherKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        assertThatIllegalStateException()
                .isThrownBy(() -> ChainBuilder.of(leaf)
                        .intermediates(intermediate)
                        .trustAnchors(otherRoot)
                        .build())
                .withMessageContaining("no issuer found");
    }

    @Test
    void trustStoreOverloadReadsCertificateEntries() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("root", root);

        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(intermediate)
                .trustStore(ks)
                .build();

        assertThat(chain.size()).isEqualTo(3);
        assertThat(chain.getRoot()).isEqualTo(root);
    }

    @Test
    void selfSignedLeafIsItsOwnAnchor() {
        KeyPair selfKeys = PkiKeys.rsa(2048);
        X509Certificate selfCert = PkiCertificate.selfSigned()
                .subject("CN=self")
                .keyPair(selfKeys)
                .validFor(Duration.ofDays(30))
                .build();

        CertChain chain = ChainBuilder.of(selfCert)
                .trustAnchors(selfCert)
                .build();

        assertThat(chain.size()).isEqualTo(1);
        assertThat(chain.getLeaf()).isEqualTo(selfCert);
        assertThat(chain.getRoot()).isEqualTo(selfCert);
    }

    @Test
    void chainFromBuilderValidatesSuccessfully() {
        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(intermediate)
                .trustAnchors(root)
                .build();

        ValidationResult result = chain.validate();
        assertThat(result.isValid()).isTrue();
        assertThat(result.isTrusted()).isTrue();
    }

    @Test
    void toValidatorExposesFurtherConfiguration() {
        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(intermediate)
                .trustAnchors(root)
                .build();

        // Compose with revocation: attach empty CRL that doesn't revoke the leaf.
        ValidationResult result = chain.toValidator()
                .crl(PkiCrl.issued()
                        .issuer(intermediate, intermediateKeys.getPrivate())
                        .nextUpdate(Duration.ofHours(24))
                        .build())
                .validate();

        // Intermediate has no CRL source but that's fine (intermediates soft-skip).
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void poolWithMultipleCandidatesPicksTheSigner() {
        // Two intermediates with the SAME subject DN. Only one actually signs the leaf.
        KeyPair imposterKeys = PkiKeys.rsa(2048);
        X509Certificate imposter = PkiCertificate.signed()
                .subject(intermediate.getSubjectX500Principal().getName())
                .publicKey(imposterKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365)).pathLength(0).build();

        CertChain chain = ChainBuilder.of(leaf)
                .intermediates(List.of(imposter, intermediate))
                .trustAnchors(root)
                .build();

        // The real intermediate must be chosen — verifies against its key.
        assertThat(chain.getCertificates().get(1)).isEqualTo(intermediate);
    }
}
