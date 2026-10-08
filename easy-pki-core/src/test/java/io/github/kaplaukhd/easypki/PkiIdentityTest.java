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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PkiIdentityTest {
    private static final KeyPair ROOT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ISSUER_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair LEAF_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT = self("CN=Identity Root", ROOT_KEYS);
    private static final X509Certificate ISSUER = PkiCertificate.signed().subject("CN=Identity Issuer")
            .keyPair(ISSUER_KEYS).issuer(ROOT, ROOT_KEYS.getPrivate()).isCA(true)
            .validFor(Duration.ofDays(20)).build();
    private static final X509Certificate LEAF = PkiCertificate.signed().subject("CN=Identity Leaf")
            .keyPair(LEAF_KEYS).issuer(ISSUER, ISSUER_KEYS.getPrivate()).validFor(Duration.ofDays(10)).build();

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC", "Ed25519"})
    void keyAndCertificateMatchForSupportedAlgorithms(String algorithm) {
        KeyPair keys = switch (algorithm) {
            case "RSA" -> PkiKeys.rsa(2048);
            case "EC" -> PkiKeys.ec(Curve.P_256);
            default -> PkiKeys.ed25519();
        };
        var certificate = self("CN=Identity", keys);
        var providers = Security.getProviders();
        var identity = PkiIdentity.of(certificate, keys.getPrivate());
        assertThat(identity.getCertificate()).isEqualTo(certificate);
        assertThat(identity.getChain()).containsExactly(certificate);
        assertThat(identity.getPrivateKey()).contains(keys.getPrivate());
        assertThat(identity.getSigner()).isNotNull();
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void chainIsCopiedOrderedAndMayOmitTheRoot() {
        var signer = PkiSigner.jca(LEAF_KEYS.getPrivate());
        var source = new ArrayList<>(List.of(LEAF, ISSUER, ROOT));
        var identity = PkiIdentity.of(signer, source);
        source.clear();
        assertThat(identity.getChain()).containsExactly(LEAF, ISSUER, ROOT);
        assertThatThrownBy(() -> identity.getChain().clear()).isInstanceOf(UnsupportedOperationException.class);
        X509Certificate[] above = {ISSUER};
        var partial = PkiIdentity.of(LEAF, signer, above);
        above[0] = ROOT;
        assertThat(partial.getChain()).containsExactly(LEAF, ISSUER);
        assertThat(PkiIdentity.of(LEAF, signer).getChain()).containsExactly(LEAF);
    }

    @Test
    void externalSigningHandleProvesPossessionWithoutAJavaPrivateKey() throws Exception {
        List<byte[]> challenges = new ArrayList<>();
        var backend = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException {
                challenges.add(data.clone());
                return backendSignature(data);
            }
        };
        var first = PkiIdentity.of(LEAF, backend, ISSUER, ROOT);
        var second = PkiIdentity.of(LEAF, backend, ISSUER, ROOT);
        assertThat(first.getSigner()).isSameAs(backend);
        assertThat(first.getPrivateKey()).isEmpty();
        assertThat(second.getCertificate()).isEqualTo(LEAF);
        assertThat(challenges).hasSize(2);
        assertThat(challenges.get(0)).isNotEqualTo(challenges.get(1));
        assertThat(challenges.get(0)).startsWith(
                "easy-pki identity key possession".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    void mismatchedKeyIsRejectedForBothFactories() {
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, ROOT_KEYS.getPrivate(), ISSUER, ROOT))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("does not match");
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, PkiSigner.jca(ROOT_KEYS.getPrivate()), ISSUER, ROOT))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("does not match");
    }

    @Test
    void wrongOrderAndMissingLinksAreRejectedBeforeCallingBackend() {
        var never = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) { throw new AssertionError("invalid chain must not invoke backend"); }
        };
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, never, ROOT, ISSUER))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("issuer name mismatch");
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, never, ROOT))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("issuer name mismatch");
    }

    @Test
    void sameNamedButWrongIssuerKeyIsRejected() {
        var impostor = PkiCertificate.selfSigned().subject(ISSUER.getSubjectX500Principal())
                .keyPair(ROOT_KEYS).validFor(Duration.ofDays(1)).isCA(true).build();
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, LEAF_KEYS.getPrivate(), impostor))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("signature mismatch");
    }

    @Test
    void duplicateAndMissingCertificatesAreRejected() {
        var signer = PkiSigner.jca(LEAF_KEYS.getPrivate());
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, signer, LEAF))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("duplicate");
        assertThatThrownBy(() -> PkiIdentity.of(signer, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, signer, new X509Certificate[]{null}))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, (PkiSigner) null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiIdentity.of(null, signer)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void backendFailureCauseIsPreserved() {
        var failure = new GeneralSecurityException("backend unavailable");
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException { throw failure; }
        };
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, signer)).isInstanceOf(IllegalArgumentException.class)
                .hasCause(failure);
    }

    @Test
    void replayedOrMutatedChallengeSignaturesCannotSatisfyProof() {
        List<byte[]> responses = new ArrayList<>();
        var recording = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException {
                byte[] response = backendSignature(data); responses.add(response); return response;
            }
        };
        PkiIdentity.of(LEAF, recording);
        var replay = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) { return responses.get(0); }
        };
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, replay)).isInstanceOf(IllegalArgumentException.class);
        var mutating = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException {
                Arrays.fill(data, (byte) 0); return backendSignature(data);
            }
        };
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, mutating)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "empty", "invalid"})
    void invalidSignaturesAreRejected(String mode) {
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] data) {
                return mode.equals("null") ? null : mode.equals("empty") ? new byte[0] : new byte[]{1,2,3};
            }
        };
        assertThatThrownBy(() -> PkiIdentity.of(LEAF, signer)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void expiredCertificateCanRepresentIdentityButDoesNotEstablishTrust() {
        var expired = PkiCertificate.selfSigned().subject("CN=Expired Identity").keyPair(LEAF_KEYS)
                .validFrom(Instant.now().minus(Duration.ofDays(2)))
                .validUntil(Instant.now().minus(Duration.ofDays(1))).build();
        assertThat(PkiIdentity.of(expired, LEAF_KEYS.getPrivate()).getCertificate()).isEqualTo(expired);
    }

    @Test
    void pkcs12IdentityAdapterPreservesKeyAndChainButRejectsTrustOnly() {
        var bundle = PkiPkcs12.create().certificate(LEAF).privateKey(LEAF_KEYS.getPrivate())
                .chain(ISSUER, ROOT).password("password").build();
        var reloaded = PkiPkcs12.load(bundle.toBytes(), "password");
        var identity = PkiIdentity.fromPkcs12(reloaded);
        assertThat(identity.getChain()).containsExactly(LEAF, ISSUER, ROOT);
        assertThat(identity.getPrivateKey()).contains(reloaded.getPrivateKey());
        assertThatThrownBy(() -> PkiIdentity.fromPkcs12(PkiPkcs12.create().certificate(ROOT)
                .password("password").build())).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trust-only");
    }

    @Test
    void pssProofAndPssSignedChainUseAllDeclaredParameters() {
        KeyPair keys = PkiKeys.rsa(2048);
        var parameters = new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA384, 18);
        var signer = PkiSigner.rsaPss(keys.getPrivate(), parameters);
        var root = PkiCertificate.selfSigned().subject("CN=PSS Identity Root")
                .signer(keys.getPublic(), signer).isCA(true).validFor(Duration.ofDays(2)).build();
        assertThat(PkiIdentity.of(root, signer).getCertificate()).isEqualTo(root);
        var leaf = PkiCertificate.signed().subject("CN=PSS Signed Leaf").keyPair(LEAF_KEYS)
                .issuer(root, signer).validFor(Duration.ofDays(1)).build();
        assertThat(PkiIdentity.of(leaf, LEAF_KEYS.getPrivate(), root).getChain()).containsExactly(leaf, root);
        var legacy = PkiSigner.jca(keys.getPrivate(), "SHA256withRSAandMGF1",
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        assertThat(PkiIdentity.of(root, legacy).getCertificate()).isEqualTo(root);
    }

    private static byte[] backendSignature(byte[] content) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(LEAF_KEYS.getPrivate()); signature.update(content); return signature.sign();
    }

    private static X509Certificate self(String name, KeyPair keys) {
        return PkiCertificate.selfSigned().subject(name).keyPair(keys).isCA(true)
                .validFor(Duration.ofDays(30)).build();
    }
}
