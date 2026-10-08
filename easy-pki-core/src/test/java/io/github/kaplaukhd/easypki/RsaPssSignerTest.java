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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class RsaPssSignerTest {
    private static final KeyPair RSA = PkiKeys.rsa(2048);
    private static final KeyPair EC = PkiKeys.ec(Curve.P_256);
    private static final byte[] MESSAGE = "explicit PSS parameters".getBytes(StandardCharsets.UTF_8);
    private static final RsaPssParameters MIXED = new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA384, 18);

    @ParameterizedTest
    @ValueSource(strings = {"default", "named", "instance"})
    void mixedDigestsAndNondefaultSaltWorkWithExplicitProvidersAndBothBuilders(String selection) throws Exception {
        Provider[] before = Security.getProviders();
        Provider sun = Signature.getInstance("RSASSA-PSS", "SunRsaSign").getProvider();
        PkiSigner signer = switch (selection) {
            case "named" -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED, sun.getName());
            case "instance" -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED, sun);
            default -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED);
        };
        assertThat(signer.signatureAlgorithm()).isEqualTo("RSASSA-PSS");
        assertParameters((PSSParameterSpec) signer.signatureParameters(), MIXED);
        assertThat(verify(MESSAGE, signer.sign(MESSAGE), MIXED.toParameterSpec())).isTrue();
        X509Certificate root = self(signer);
        X509Certificate leaf = PkiCertificate.signed().subject("CN=PSS Leaf").keyPair(EC)
                .issuer(root, signer).validFor(Duration.ofHours(1)).build();
        for (X509Certificate certificate : List.of(root, leaf)) {
            assertMetadata(certificate, MIXED);
            assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), MIXED.toParameterSpec())).isTrue();
            assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), RsaPssParameters.sha256().toParameterSpec()))
                    .isFalse();
            AlgorithmParameters decoded = AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
            decoded.init(certificate.getSigAlgParams());
            PSSParameterSpec recorded = decoded.getParameterSpec(PSSParameterSpec.class);
            assertParameters(recorded, MIXED);
            assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), recorded)).isTrue();
            X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509", "SUN")
                    .generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            parsed.verify(RSA.getPublic(), sun);
        }
        assertThat(Security.getProviders()).containsExactly(before);
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void supportedDigestsAndZeroSaltVerifyIndependently(HashAlgorithm digest) throws Exception {
        RsaPssParameters parameters = new RsaPssParameters(digest, digest, 0);
        PkiSigner signer = PkiSigner.rsaPss(RSA.getPrivate(), parameters);
        X509Certificate certificate = self(signer);
        assertMetadata(certificate, parameters);
        assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), parameters.toParameterSpec())).isTrue();
    }

    @Test
    void defaultPresetAndSignerReuseKeepTheirExactParameters() throws Exception {
        RsaPssParameters parameters = RsaPssParameters.sha256();
        assertThat(parameters).isEqualTo(new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA256, 32));
        PkiSigner signer = PkiSigner.rsaPss(RSA.getPrivate(), parameters);
        assertThat(verify(MESSAGE, signer.sign(MESSAGE), parameters.toParameterSpec())).isTrue();
        byte[] second = "another operation".getBytes(StandardCharsets.UTF_8);
        assertThat(verify(second, signer.sign(second), parameters.toParameterSpec())).isTrue();
    }

    @Test
    void customPssBackendDeclaresTheSameParametersUsedInTheCertificate() throws Exception {
        PkiSigner delegate = PkiSigner.rsaPss(RSA.getPrivate(), MIXED);
        PkiSigner signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "RSASSA-PSS"; }
            @Override public PSSParameterSpec signatureParameters() { return MIXED.toParameterSpec(); }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException { return delegate.sign(content); }
        };
        X509Certificate certificate = self(signer);
        assertMetadata(certificate, MIXED);
        assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), MIXED.toParameterSpec())).isTrue();
    }

    @Test
    void existingNamedPssAlgorithmsKeepWorkingWithoutNewConfiguration() throws Exception {
        PkiSigner signer = PkiSigner.jca(RSA.getPrivate(), "SHA256withRSAandMGF1", new BouncyCastleProvider());
        assertThat(signer.signatureParameters()).isNull();
        X509Certificate certificate = self(signer);
        assertMetadata(certificate, RsaPssParameters.sha256());
        assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), RsaPssParameters.sha256().toParameterSpec()))
                .isTrue();
    }

    @Test
    void unregisteredBcSupportsMatchingDigestsAndRejectsUnsupportedMixedDigests() throws Exception {
        Provider[] before = Security.getProviders();
        Provider provider = new BouncyCastleProvider();
        RsaPssParameters parameters = new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA256, 18);
        PkiSigner signer = PkiSigner.rsaPss(RSA.getPrivate(), parameters, provider);
        X509Certificate certificate = self(signer);
        assertMetadata(certificate, parameters);
        assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), parameters.toParameterSpec())).isTrue();
        PkiSigner unsupported = PkiSigner.rsaPss(RSA.getPrivate(), MIXED, provider);
        assertThatThrownBy(() -> unsupported.sign(MESSAGE)).isInstanceOf(InvalidAlgorithmParameterException.class);
        assertThat(Security.getProviders()).containsExactly(before);
    }

    @Test
    void opaquePssKeyIsNotExportedAndProviderRemainsUnregistered() throws Exception {
        Provider[] before = Security.getProviders();
        OpaqueProvider provider = new OpaqueProvider(false);
        OpaqueKey key = new OpaqueKey(RSA.getPrivate());
        PkiSigner signer = PkiSigner.rsaPss(key, MIXED, provider);
        X509Certificate certificate = self(signer);
        assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), MIXED.toParameterSpec())).isTrue();
        assertThat(provider.signatures.get()).isEqualTo(1);
        assertThat(key.exports.get()).isZero();
        assertThat(Security.getProviders()).containsExactly(before);
        assertThat(Security.getProvider(provider.getName())).isNull();
    }

    @Test
    void defaultProviderSelectionUsesTheOpaqueKeyBeforeApplyingPssParameters() throws Exception {
        Provider[] before = Security.getProviders();
        OpaqueProvider provider = new OpaqueProvider(false);
        OpaqueKey key = new OpaqueKey(RSA.getPrivate());
        assertThat(Security.getProvider(provider.getName())).isNull();
        try {
            assertThat(Security.addProvider(provider)).isEqualTo(before.length + 1);
            PkiSigner signer = PkiSigner.rsaPss(key, MIXED);
            assertThat(verify(MESSAGE, signer.sign(MESSAGE), MIXED.toParameterSpec())).isTrue();
            X509Certificate certificate = self(signer);
            assertMetadata(certificate, MIXED);
            assertThat(verify(certificate.getTBSCertificate(), certificate.getSignature(), MIXED.toParameterSpec())).isTrue();
            assertThat(provider.signatures.get()).isEqualTo(2);
            assertThat(key.exports.get()).isZero();
        } finally {
            Security.removeProvider(provider.getName());
            assertThat(Security.getProviders()).containsExactly(before);
        }
    }

    @Test
    void identityProvesOpaquePssKeyPossessionAndRejectsAWrongLeafKeyWithoutExport() {
        Provider[] before = Security.getProviders();
        OpaqueProvider provider = new OpaqueProvider(false);
        OpaqueKey key = new OpaqueKey(RSA.getPrivate());
        PkiSigner signer = PkiSigner.rsaPss(key, MIXED, provider);
        X509Certificate issuer = PkiCertificate.selfSigned().subject("CN=Opaque Identity Issuer")
                .keyPair(EC).isCA(true).validFor(Duration.ofDays(1)).build();
        X509Certificate leaf = PkiCertificate.signed().subject("CN=Opaque Identity Leaf")
                .publicKey(RSA.getPublic()).issuer(issuer, EC.getPrivate())
                .validFor(Duration.ofHours(1)).build();

        PkiIdentity identity = PkiIdentity.of(leaf, signer, issuer);
        assertThat(identity.getCertificate()).isEqualTo(leaf);
        assertThat(identity.getChain()).containsExactly(leaf, issuer);
        assertThat(identity.getSigner()).isSameAs(signer);
        assertThat(identity.getPrivateKey()).isEmpty();
        assertThat(provider.signatures.get()).isEqualTo(1);
        assertThat(key.exports.get()).isZero();

        X509Certificate wrongLeaf = PkiCertificate.signed().subject("CN=Wrong Opaque Identity Leaf")
                .publicKey(PkiKeys.rsa(2048).getPublic()).issuer(issuer, EC.getPrivate())
                .validFor(Duration.ofHours(1)).build();
        assertThatThrownBy(() -> PkiIdentity.of(wrongLeaf, signer, issuer))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("does not match the leaf certificate key");
        assertThat(provider.signatures.get()).isEqualTo(2);
        assertThat(key.exports.get()).isZero();
        assertThat(Security.getProviders()).containsExactly(before);
        assertThat(Security.getProvider(provider.getName())).isNull();
    }

    @Test
    void unsupportedProviderParametersFailWithoutFallback() {
        OpaqueProvider provider = new OpaqueProvider(true);
        PkiSigner signer = PkiSigner.rsaPss(new OpaqueKey(RSA.getPrivate()), MIXED, provider);
        assertThatThrownBy(() -> signer.sign(MESSAGE)).isInstanceOf(InvalidAlgorithmParameterException.class);
        assertThatThrownBy(() -> self(signer)).isInstanceOf(IllegalStateException.class)
                .hasCauseInstanceOf(InvalidAlgorithmParameterException.class);
        assertThat(provider.signatures.get()).isZero();
    }

    @Test
    void providerWithoutPssAndUnknownProviderNameFailWithoutFallback() {
        Provider empty = new Provider("PssUnsupportedTest", "1.0", "no signature algorithms") {
            private static final long serialVersionUID = 1L;
        };
        PkiSigner signer = PkiSigner.rsaPss(RSA.getPrivate(), MIXED, empty);
        assertThatThrownBy(() -> signer.sign(MESSAGE)).isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED, "missing-pss-provider"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("No registered JCA provider");
    }

    @Test
    void genericPssCannotChooseImplicitParameters() {
        assertThatThrownBy(() -> PkiSigner.jca(RSA.getPrivate(), "RSASSA-PSS"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("explicit");
        assertRejectedBeforeBackend("RSASSA-PSS", null);
    }

    @ParameterizedTest
    @MethodSource("unsupportedParameters")
    void customBackendUnsupportedParametersFailBeforeSigning(AlgorithmParameterSpec parameters) {
        assertRejectedBeforeBackend("RSASSA-PSS", parameters);
    }

    static Stream<AlgorithmParameterSpec> unsupportedParameters() {
        return Stream.of(
                new ECGenParameterSpec("secp256r1"),
                new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 32, 1),
                new PSSParameterSpec("SHA-256", "MGF1", null, 32, 1),
                new PSSParameterSpec("SHA-256", "MGF1", new ECGenParameterSpec("secp256r1"), 32, 1),
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2),
                new PSSParameterSpec("MD5", "MGF1", MGF1ParameterSpec.SHA256, 32, 1),
                new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("MD5"), 32, 1));
    }

    @Test
    void pssParametersCannotBeAttachedToAnUnrelatedOrContradictoryAlgorithm() {
        assertRejectedBeforeBackend("SHA256withRSA", MIXED.toParameterSpec());
        assertRejectedBeforeBackend("SHA256withECDSA", MIXED.toParameterSpec());
        assertRejectedBeforeBackend("SHA384withRSAandMGF1", MIXED.toParameterSpec());
    }

    @Test
    void impossibleSaltAndWrongKeyFailWithoutReturningACertificate() {
        PkiSigner largeSalt = PkiSigner.rsaPss(RSA.getPrivate(), new RsaPssParameters(HashAlgorithm.SHA512, HashAlgorithm.SHA256, 512));
        assertThatThrownBy(() -> largeSalt.sign(MESSAGE)).isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> self(largeSalt)).isInstanceOf(IllegalStateException.class);
        PkiSigner wrongKey = PkiSigner.rsaPss(EC.getPrivate(), MIXED);
        assertThatThrownBy(() -> wrongKey.sign(MESSAGE)).isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void invalidConfigurationsAreRejected() {
        assertThatThrownBy(() -> new RsaPssParameters(null, HashAlgorithm.SHA256, 32)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RsaPssParameters(HashAlgorithm.SHA256, null, 32)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA256, -1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiSigner.rsaPss(null, MIXED)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiSigner.rsaPss(RSA.getPrivate(), null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED, (Provider) null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkiSigner.rsaPss(RSA.getPrivate(), MIXED, (String) null)).isInstanceOf(NullPointerException.class);
    }

    private static void assertRejectedBeforeBackend(String algorithm, AlgorithmParameterSpec parameters) {
        PkiSigner signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return algorithm; }
            @Override public AlgorithmParameterSpec signatureParameters() { return parameters; }
            @Override public byte[] sign(byte[] content) { throw new AssertionError("backend must not be called"); }
        };
        assertThatThrownBy(() -> self(signer)).isInstanceOf(IllegalArgumentException.class);
    }

    private static X509Certificate self(PkiSigner signer) {
        return PkiCertificate.selfSigned().subject("CN=PSS Root").signer(RSA.getPublic(), signer)
                .isCA(true).validFor(Duration.ofDays(1)).build();
    }

    private static boolean verify(byte[] message, byte[] signature, PSSParameterSpec parameters) throws Exception {
        Signature verifier = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
        verifier.setParameter(parameters);
        verifier.initVerify(RSA.getPublic());
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static void assertParameters(PSSParameterSpec actual, RsaPssParameters expected) {
        assertThat(actual.getDigestAlgorithm()).isEqualTo(expected.digestAlgorithm().jcaName());
        assertThat(actual.getMGFAlgorithm()).isEqualTo("MGF1");
        assertThat(((MGF1ParameterSpec) actual.getMGFParameters()).getDigestAlgorithm())
                .isEqualTo(expected.mgfDigestAlgorithm().jcaName());
        assertThat(actual.getSaltLength()).isEqualTo(expected.saltLength());
        assertThat(actual.getTrailerField()).isEqualTo(1);
    }

    private static void assertMetadata(X509Certificate certificate, RsaPssParameters expected) throws Exception {
        var holder = new JcaX509CertificateHolder(certificate);
        assertThat(holder.getSignatureAlgorithm()).isEqualTo(holder.toASN1Structure().getTBSCertificate().getSignature());
        assertThat(holder.getSignatureAlgorithm().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_RSASSA_PSS);
        RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(holder.getSignatureAlgorithm().getParameters());
        assertThat(parameters.getSaltLength().intValueExact()).isEqualTo(expected.saltLength());
        assertThat(parameters.getTrailerField().intValueExact()).isEqualTo(1);
        assertThat(parameters.getMaskGenAlgorithm().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_mgf1);
        if (expected.equals(MIXED)) {
            assertThat(parameters.getHashAlgorithm().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_sha256);
            assertThat(AlgorithmIdentifier.getInstance(parameters.getMaskGenAlgorithm().getParameters()).getAlgorithm())
                    .isEqualTo(NISTObjectIdentifiers.id_sha384);
        }
    }

    private static final class OpaqueKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final PrivateKey delegate;
        private final AtomicInteger exports = new AtomicInteger();
        private OpaqueKey(PrivateKey delegate) { this.delegate = delegate; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() {
            exports.incrementAndGet();
            throw new AssertionError("key handle cannot be exported");
        }
    }

    private static final class OpaqueProvider extends Provider {
        private static final long serialVersionUID = 1L;
        private final AtomicInteger signatures = new AtomicInteger();
        private OpaqueProvider(boolean rejectParameters) {
            super("OpaquePssTest", "1.0", "Synthetic PSS key-handle provider");
            putService(new Service(this, "Signature", "RSASSA-PSS", OpaqueSignature.class.getName(), List.of(), Map.of()) {
                @Override public Object newInstance(Object parameter) { return new OpaqueSignature(signatures, rejectParameters); }
            });
        }
    }

    @SuppressWarnings("deprecation")
    private static final class OpaqueSignature extends SignatureSpi {
        private final AtomicInteger signatures;
        private final boolean rejectParameters;
        private Signature delegate;
        private OpaqueSignature(AtomicInteger signatures, boolean rejectParameters) {
            this.signatures = signatures;
            this.rejectParameters = rejectParameters;
        }
        private Signature delegate() throws InvalidKeyException {
            try {
                if (delegate == null) delegate = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
                return delegate;
            } catch (GeneralSecurityException e) {
                throw new InvalidKeyException(e);
            }
        }
        @Override protected void engineInitVerify(PublicKey key) throws InvalidKeyException { delegate().initVerify(key); }
        @Override protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
            if (!(key instanceof OpaqueKey handle)) throw new InvalidKeyException("expected opaque handle");
            delegate().initSign(handle.delegate);
        }
        @Override protected void engineUpdate(byte b) throws SignatureException { delegate.update(b); }
        @Override protected void engineUpdate(byte[] b, int offset, int length) throws SignatureException { delegate.update(b, offset, length); }
        @Override protected byte[] engineSign() throws SignatureException { signatures.incrementAndGet(); return delegate.sign(); }
        @Override protected boolean engineVerify(byte[] signature) throws SignatureException { return delegate.verify(signature); }
        @Override protected void engineSetParameter(AlgorithmParameterSpec parameters) throws InvalidAlgorithmParameterException {
            if (rejectParameters) throw new InvalidAlgorithmParameterException("provider rejects these PSS parameters");
            try {
                delegate().setParameter(parameters);
            } catch (GeneralSecurityException e) {
                throw new InvalidAlgorithmParameterException(e);
            }
        }
        @Override protected void engineSetParameter(String name, Object value) { throw new UnsupportedOperationException(); }
        @Override protected Object engineGetParameter(String name) { throw new UnsupportedOperationException(); }
    }
}
