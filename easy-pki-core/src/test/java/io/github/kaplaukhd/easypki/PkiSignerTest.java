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

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PkiSignerTest {
    private static final KeyPair RSA = PkiKeys.rsa(2048);
    private static final KeyPair EC = PkiKeys.ec(Curve.P_256);
    private static final byte[] MESSAGE = "independent signing operation".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @ValueSource(strings = {"SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA384withECDSA"})
    void jcaSignersWorkForBothCertificateBuilders(String algorithm) throws Exception {
        KeyPair keys = algorithm.endsWith("RSA") ? RSA : EC;
        PkiSigner signer = PkiSigner.jca(keys.getPrivate(), algorithm);
        assertThat(signer.signatureAlgorithm()).isEqualTo(algorithm);
        verify(keys.getPublic(), algorithm, MESSAGE, signer.sign(MESSAGE));
        X509Certificate root = self(keys.getPublic(), signer);
        X509Certificate leaf = issued(root, signer);
        root.verify(keys.getPublic());
        leaf.verify(keys.getPublic());
        assertThat(root.getSigAlgName()).isEqualToIgnoringCase(algorithm);
        assertThat(leaf.getSigAlgName()).isEqualToIgnoringCase(algorithm);
        assertAlgorithmMetadataMatches(root);
        assertAlgorithmMetadataMatches(leaf);
    }

    @Test
    void oldPrivateKeyPathsRetainDefaultsAndOverrides() throws Exception {
        var root = PkiCertificate.selfSigned().subject("CN=Legacy").keyPair(RSA)
                .signatureAlgorithm("SHA384withRSA").validFor(Duration.ofDays(1)).build();
        root.verify(RSA.getPublic());
        var leaf = PkiCertificate.signed().subject("CN=Leaf").keyPair(EC)
                .issuer(root, RSA.getPrivate()).signatureAlgorithm("SHA512withRSA")
                .validFor(Duration.ofHours(1)).build();
        leaf.verify(RSA.getPublic());
        assertThat(leaf.getSigAlgName()).isEqualToIgnoringCase("SHA512withRSA");
        assertThat(PkiSigner.jca(RSA.getPrivate()).signatureAlgorithm()).isEqualTo("SHA256withRSA");
        assertThat(PkiSigner.jca(EC.getPrivate()).signatureAlgorithm()).isEqualTo("SHA256withECDSA");
    }

    @Test
    void customBackendReceivesExactTbsBytesWithoutAnyPrivateKeyInTheBuilder() throws Exception {
        List<byte[]> messages = new ArrayList<>();
        PkiSigner signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException {
                messages.add(content.clone());
                Signature operation = Signature.getInstance(signatureAlgorithm());
                operation.initSign(EC.getPrivate());
                operation.update(content);
                return operation.sign();
            }
        };
        var root = self(EC.getPublic(), signer);
        var leaf = issued(root, signer);
        assertThat(messages).hasSize(2);
        assertThat(messages.get(0)).isEqualTo(root.getTBSCertificate());
        assertThat(messages.get(1)).isEqualTo(leaf.getTBSCertificate());
        root.verify(EC.getPublic());
        leaf.verify(EC.getPublic());
    }

    @Test
    void providerAcceptsOpaqueKeyWithoutExportOrGlobalRegistration() throws Exception {
        Provider[] before = Security.getProviders();
        var handle = new OpaqueKey(RSA.getPrivate());
        var provider = new OpaqueProvider();
        PkiSigner signer = PkiSigner.jca(handle, "SHA256withRSA", provider);
        var root = self(RSA.getPublic(), signer);
        var leaf = issued(root, signer);
        root.verify(RSA.getPublic());
        leaf.verify(RSA.getPublic());
        assertThat(provider.signatures.get()).isEqualTo(2);
        assertThat(handle.exportAttempts.get()).isZero();
        assertThat(Security.getProviders()).containsExactly(before);
        assertThat(Security.getProvider(provider.getName())).isNull();
    }

    @Test
    void explicitProviderNameIsResolvedAndMissingProviderDoesNotFallBack() throws Exception {
        Provider provider = Signature.getInstance("SHA256withRSA").getProvider();
        verify(RSA.getPublic(), "SHA256withRSA", MESSAGE,
                PkiSigner.jca(RSA.getPrivate(), "SHA256withRSA", provider.getName()).sign(MESSAGE));
        assertThatThrownBy(() -> PkiSigner.jca(RSA.getPrivate(), "SHA256withRSA", "easy-pki-missing-provider"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("No registered JCA provider");
    }

    @Test
    void explicitUnsupportedProviderFailsInsteadOfUsingDefaultProvider() {
        Provider empty = new Provider("NoSigningAlgorithms", "1.0", "test-only empty provider") {
            private static final long serialVersionUID = 1L;
        };
        var signer = PkiSigner.jca(RSA.getPrivate(), "SHA256withRSA", empty);
        assertThatThrownBy(() -> signer.sign(MESSAGE)).isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> self(RSA.getPublic(), signer)).isInstanceOf(IllegalStateException.class)
                .hasCauseInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void jcaSignerAndBuilderAreReusableWithoutAccumulatedData() throws Exception {
        var signer = PkiSigner.jca(EC.getPrivate());
        var builder = PkiCertificate.selfSigned().subject("CN=Repeated").signer(EC.getPublic(), signer)
                .validFor(Duration.ofDays(1));
        var first = builder.build();
        var second = builder.build();
        first.verify(EC.getPublic());
        second.verify(EC.getPublic());
        assertThat(first.getSerialNumber()).isNotEqualTo(second.getSerialNumber());
        var executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> calls = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                byte[] message = ("message-" + i).getBytes(StandardCharsets.UTF_8);
                calls.add(() -> {
                    verify(EC.getPublic(), signer.signatureAlgorithm(), message, signer.sign(message));
                    return true;
                });
            }
            for (var result : executor.invokeAll(calls)) assertThat(result.get()).isTrue();
        } finally { executor.shutdownNow(); }
    }

    @Test
    void checkedBackendFailureIsPreservedAndNoCertificateIsReturned() {
        GeneralSecurityException failure = new GeneralSecurityException("backend unavailable");
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withRSA"; }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException { throw failure; }
        };
        assertThatThrownBy(() -> self(RSA.getPublic(), signer)).isInstanceOf(IllegalStateException.class)
                .hasCause(failure);
        var root = self(RSA.getPublic(), PkiSigner.jca(RSA.getPrivate()));
        assertThatThrownBy(() -> issued(root, signer)).isInstanceOf(IllegalStateException.class).hasCause(failure);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void nullAndEmptyBackendSignaturesAreRejected(boolean nullResult) {
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withRSA"; }
            @Override public byte[] sign(byte[] content) { return nullResult ? null : new byte[0]; }
        };
        assertThatThrownBy(() -> self(RSA.getPublic(), signer)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("empty signature");
    }

    @Test
    void explicitSignersOwnTheirAlgorithmsInEitherConfigurationOrder() {
        var signer = PkiSigner.jca(RSA.getPrivate());
        var root = self(RSA.getPublic(), signer);
        assertThatThrownBy(() -> PkiCertificate.selfSigned().signer(RSA.getPublic(), signer)
                .signatureAlgorithm("SHA384withRSA")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiCertificate.selfSigned().signatureAlgorithm("SHA384withRSA")
                .signer(RSA.getPublic(), signer)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiCertificate.signed().issuer(root, signer)
                .signatureAlgorithm("SHA384withRSA")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiCertificate.signed().signatureAlgorithm("SHA384withRSA")
                .issuer(root, signer)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void replacingSignerWithLegacyKeyDoesNotReuseOldSigner() throws Exception {
        PkiSigner failing = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] bytes) { throw new AssertionError("obsolete signer was used"); }
        };
        var root = PkiCertificate.selfSigned().subject("CN=Replaced").signer(EC.getPublic(), failing)
                .keyPair(RSA).signatureAlgorithm("SHA384withRSA").validFor(Duration.ofDays(1)).build();
        root.verify(RSA.getPublic());
        var leaf = PkiCertificate.signed().subject("CN=Leaf").keyPair(EC)
                .issuer(root, failing).issuer(root, RSA.getPrivate()).validFor(Duration.ofHours(1)).build();
        leaf.verify(RSA.getPublic());
    }

    @Test
    void explicitSignerReplacesTheOldPrivateKeyAndPublicKey() throws Exception {
        var signer = PkiSigner.jca(EC.getPrivate());
        var root = PkiCertificate.selfSigned().subject("CN=Replacement").keyPair(RSA)
                .signer(EC.getPublic(), signer).validFor(Duration.ofDays(1)).build();
        assertThat(root.getPublicKey()).isEqualTo(EC.getPublic());
        root.verify(EC.getPublic());
        var leaf = PkiCertificate.signed().subject("CN=Replacement Leaf").keyPair(RSA)
                .issuer(root, RSA.getPrivate()).issuer(root, signer).validFor(Duration.ofHours(1)).build();
        assertThat(leaf.getPublicKey()).isEqualTo(RSA.getPublic());
        leaf.verify(EC.getPublic());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.NullSource
    @ValueSource(strings = {"", "unmapped-signature"})
    void badCustomAlgorithmMetadataFailsBeforeCallingBackend(String algorithm) {
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return algorithm; }
            @Override public byte[] sign(byte[] content) { throw new AssertionError("backend must not be called"); }
        };
        assertThatThrownBy(() -> self(RSA.getPublic(), signer))
                .isInstanceOfAny(IllegalArgumentException.class, NullPointerException.class);
    }

    @Test
    void invalidConfigurationFailsBeforeSigning() {
        assertThatThrownBy(() -> PkiSigner.jca(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiSigner.jca(RSA.getPrivate(), " ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiSigner.jca(RSA.getPrivate(), "not-a-signature"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiSigner.jca(RSA.getPrivate(), "SHA256withRSA", (Provider) null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiCertificate.selfSigned().signer(null, PkiSigner.jca(RSA.getPrivate())))
                .isInstanceOf(NullPointerException.class);
    }

    private static X509Certificate self(PublicKey key, PkiSigner signer) {
        return PkiCertificate.selfSigned().subject("CN=Signer Root").signer(key, signer)
                .isCA(true).validFor(Duration.ofDays(1)).build();
    }

    private static X509Certificate issued(X509Certificate issuer, PkiSigner signer) {
        return PkiCertificate.signed().subject("CN=Signer Leaf").keyPair(EC).issuer(issuer, signer)
                .validFor(Duration.ofHours(1)).build();
    }

    private static void verify(PublicKey key, String algorithm, byte[] data, byte[] signature) throws Exception {
        Signature verification = Signature.getInstance(algorithm);
        verification.initVerify(key);
        verification.update(data);
        assertThat(verification.verify(signature)).isTrue();
    }

    private static void assertAlgorithmMetadataMatches(X509Certificate certificate) throws Exception {
        var holder = new JcaX509CertificateHolder(certificate);
        assertThat(holder.toASN1Structure().getTBSCertificate().getSignature())
                .isEqualTo(holder.getSignatureAlgorithm());
    }

    private static final class OpaqueKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final PrivateKey delegate;
        private final AtomicInteger exportAttempts = new AtomicInteger();
        OpaqueKey(PrivateKey delegate) { this.delegate = delegate; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() {
            exportAttempts.incrementAndGet();
            throw new AssertionError("opaque key cannot be exported");
        }
    }

    private static final class OpaqueProvider extends Provider {
        private static final long serialVersionUID = 1L;
        private final AtomicInteger signatures = new AtomicInteger();
        OpaqueProvider() {
            super("EasyPkiOpaqueTest", "1.0", "Synthetic key-handle provider; no real HSM");
            putService(new Service(this, "Signature", "SHA256withRSA", OpaqueSignature.class.getName(), List.of(), Map.of()) {
                @Override public Object newInstance(Object parameter) { return new OpaqueSignature(signatures); }
            });
        }
    }

    @SuppressWarnings("deprecation")
    private static final class OpaqueSignature extends SignatureSpi {
        private final AtomicInteger signatures;
        private Signature delegate;
        OpaqueSignature(AtomicInteger signatures) { this.signatures = signatures; }
        private Signature signature() throws InvalidKeyException {
            try { return Signature.getInstance("SHA256withRSA"); }
            catch (GeneralSecurityException e) { throw new InvalidKeyException(e); }
        }
        @Override protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
            delegate = signature(); delegate.initVerify(key);
        }
        @Override protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
            if (!(key instanceof OpaqueKey handle)) throw new InvalidKeyException("expected opaque handle");
            delegate = signature(); delegate.initSign(handle.delegate);
        }
        @Override protected void engineUpdate(byte b) throws SignatureException { delegate.update(b); }
        @Override protected void engineUpdate(byte[] b, int offset, int length) throws SignatureException {
            delegate.update(b, offset, length);
        }
        @Override protected byte[] engineSign() throws SignatureException {
            signatures.incrementAndGet(); return delegate.sign();
        }
        @Override protected boolean engineVerify(byte[] signature) throws SignatureException {
            return delegate.verify(signature);
        }
        @Override protected void engineSetParameter(String parameter, Object value) { throw new UnsupportedOperationException(); }
        @Override protected Object engineGetParameter(String parameter) { throw new UnsupportedOperationException(); }
    }
}
