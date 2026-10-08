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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PkiCsrCreationTest {
    private static final KeyPair RSA = PkiKeys.rsa(2048);
    private static final KeyPair EC = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ED25519 = PkiKeys.ed25519();

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC", "Ed25519"})
    void keyPairDefaultsProduceVerifiablePortableRequests(String keyType) throws Exception {
        KeyPair keys = switch (keyType) {
            case "RSA" -> RSA;
            case "EC" -> EC;
            default -> ED25519;
        };
        String algorithm = switch (keyType) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> "Ed25519";
        };
        CsrRequest request = PkiCsr.create().subject("CN=Request,O=Example").keyPair(keys).build();
        PKCS10CertificationRequest bc = new PKCS10CertificationRequest(request.toDer());
        assertThat(bc.getAttributes()).isEmpty();
        assertThat(request.getSubject()).isEqualTo(new X500Principal("CN=Request,O=Example"));
        assertThat(request.getPublicKey().getEncoded()).isEqualTo(keys.getPublic().getEncoded());
        assertThat(request.verifySignature()).isTrue();
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keys.getPublic());
        verifier.update(bc.toASN1Structure().getCertificationRequestInfo().getEncoded("DER"));
        assertThat(verifier.verify(bc.getSignature())).isTrue();
        assertThat(PkiCsr.fromPem(request.toPem()).toDer()).isEqualTo(request.toDer());
    }

    @ParameterizedTest
    @ValueSource(strings = {"CN=host,O=Acme,C=US", "CN=Doe\\, Jane+UID=42,O=Acme,C=US",
            "CN=\\#literal,O=Acme", "CN=Тест,O=Компания,C=RU", ""})
    void subjectStringAndPrincipalKeepJcaRdnEncoding(String dn) {
        X500Principal expected = new X500Principal(dn);
        CsrRequest stringRequest = PkiCsr.create().subject(dn).keyPair(EC).build();
        CsrRequest principalRequest = PkiCsr.create().subject(expected).keyPair(EC).build();
        assertThat(stringRequest.getSubject().getEncoded()).isEqualTo(expected.getEncoded());
        assertThat(principalRequest.getSubject().getEncoded()).isEqualTo(expected.getEncoded());
    }

    @Test
    void fluentDnPreservesDisplayOrderAndLiteralEscaping() {
        CsrRequest request = PkiCsr.create().subject(dn -> dn.cn("Doe, Jane+Admin").o("Acme").c("US"))
                .keyPair(EC).build();
        assertThat(request.getSubject()).isEqualTo(new X500Principal("CN=Doe\\, Jane\\+Admin,O=Acme,C=US"));
        assertThat(PkiCsr.create().subject(dn -> {}).keyPair(EC).build().getSubject())
                .isEqualTo(new X500Principal(""));
    }

    @Test
    void requestedExtensionsUseExactlyOnePkcs9AttributeAndValue() throws Exception {
        CsrRequest request = PkiCsr.create().subject("CN=api.example.test").keyPair(EC)
                .san(s -> s.dns("api.example.test").ip("192.0.2.10").ip("2001:db8::1"))
                .san(s -> s.email("user@example.test").uri("https://example.test/service"))
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE).keyUsage(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER).extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
                .isCA(false).build();
        PKCS10CertificationRequest bc = new PKCS10CertificationRequest(request.toDer());
        assertThat(bc.getAttributes()).hasSize(1);
        var attribute = bc.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0];
        assertThat(attribute.getAttrValues()).hasSize(1);
        Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
        assertThat(extensions.getExtensionOIDs()).hasSize(4);
        assertThat(extensions.getExtension(Extension.subjectKeyIdentifier)).isNull();
        assertThat(extensions.getExtension(Extension.authorityKeyIdentifier)).isNull();
        assertThat(extensions.getExtension(Extension.basicConstraints).isCritical()).isTrue();
        assertThat(BasicConstraints.fromExtensions(extensions).isCA()).isFalse();
        assertThat(extensions.getExtension(Extension.keyUsage).isCritical()).isTrue();
        var keyUsage = org.bouncycastle.asn1.x509.KeyUsage.fromExtensions(extensions);
        assertThat(keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment)).isTrue();
        var purposes = org.bouncycastle.asn1.x509.ExtendedKeyUsage.fromExtensions(extensions);
        assertThat(purposes.getUsages()).containsExactly(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);
        assertThat(extensions.getExtension(Extension.extendedKeyUsage).isCritical()).isFalse();
        assertThat(extensions.getExtension(Extension.subjectAlternativeName).isCritical()).isFalse();
        GeneralName[] names = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName).getNames();
        assertThat(names).hasSize(5);
        assertThat(names[0]).isEqualTo(new GeneralName(GeneralName.dNSName, "api.example.test"));
        assertThat(names[1]).isEqualTo(new GeneralName(GeneralName.iPAddress, "192.0.2.10"));
        assertThat(names[2]).isEqualTo(new GeneralName(GeneralName.iPAddress, "2001:db8::1"));
        assertThat(names[3]).isEqualTo(new GeneralName(GeneralName.rfc822Name, "user@example.test"));
        assertThat(names[4]).isEqualTo(new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.test/service"));
    }

    @Test
    void caConstraintsAreIncludedOnlyWhenRequested() throws Exception {
        CsrRequest request = PkiCsr.create().subject("CN=Requested CA").keyPair(EC).pathLength(2).build();
        Extensions extensions = new PKCS10CertificationRequest(request.toDer()).getRequestedExtensions();
        assertThat(extensions.getExtensionOIDs()).containsExactly(Extension.basicConstraints);
        assertThat(BasicConstraints.fromExtensions(extensions).isCA()).isTrue();
        assertThat(BasicConstraints.fromExtensions(extensions).getPathLenConstraint()).isEqualTo(BigInteger.valueOf(2));
    }

    @Test
    void rawExtensionRetainsOidCriticalityAndInnerDerBytes() throws Exception {
        byte[] value = new DERUTF8String("requested opaque value").getEncoded("DER");
        CsrRequest request = PkiCsr.create().subject("CN=Custom").keyPair(EC)
                .extension(new CsrExtension("1.2.3.4.5", true, value)).build();
        Extension extension = new PKCS10CertificationRequest(request.toDer()).getRequestedExtensions()
                .getExtension(new ASN1ObjectIdentifier("1.2.3.4.5"));
        assertThat(extension.isCritical()).isTrue();
        assertThat(extension.getExtnValue().getOctets()).isEqualTo(value);
    }

    @Test
    void customBackendReceivesExactCertificationRequestInfo() throws Exception {
        List<byte[]> messages = new ArrayList<>();
        PkiSigner signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException {
                messages.add(content.clone());
                return PkiSigner.jca(EC.getPrivate()).sign(content);
            }
        };
        var builder = PkiCsr.create().subject("CN=External").signer(EC.getPublic(), signer);
        CsrRequest first = builder.build();
        byte[] firstDer = first.toDer();
        CsrRequest second = builder.san(s -> s.dns("example.test")).build();
        assertThat(messages).hasSize(2);
        assertThat(messages.get(0)).isEqualTo(new PKCS10CertificationRequest(firstDer)
                .toASN1Structure().getCertificationRequestInfo().getEncoded("DER"));
        assertThat(messages.get(1)).isEqualTo(new PKCS10CertificationRequest(second.toDer())
                .toASN1Structure().getCertificationRequestInfo().getEncoded("DER"));
        assertThat(first.toDer()).isEqualTo(firstDer);
        assertThat(new PKCS10CertificationRequest(first.toDer()).getAttributes()).isEmpty();
    }

    @Test
    void explicitRsaPssParametersAreEncodedAndUsed() throws Exception {
        RsaPssParameters parameters = new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA384, 20);
        CsrRequest request = PkiCsr.create().subject("CN=PSS")
                .signer(RSA.getPublic(), PkiSigner.rsaPss(RSA.getPrivate(), parameters)).build();
        PKCS10CertificationRequest bc = new PKCS10CertificationRequest(request.toDer());
        assertThat(bc.getSignatureAlgorithm().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_RSASSA_PSS);
        var encoded = RSASSAPSSparams.getInstance(bc.getSignatureAlgorithm().getParameters());
        assertThat(encoded.getSaltLength()).isEqualTo(BigInteger.valueOf(20));
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(parameters.toParameterSpec());
        verifier.initVerify(RSA.getPublic());
        verifier.update(bc.toASN1Structure().getCertificationRequestInfo().getEncoded("DER"));
        assertThat(verifier.verify(bc.getSignature())).isTrue();
        assertThat(request.verifySignature()).isTrue();
    }

    @Test
    void explicitProviderSignsOpaqueHandleWithoutExportOrGlobalRegistration() {
        Provider[] before = Security.getProviders();
        var key = new OpaqueKey(RSA.getPrivate());
        var provider = new OpaqueProvider();
        CsrRequest request = PkiCsr.create().subject("CN=Opaque")
                .signer(RSA.getPublic(), PkiSigner.jca(key, "SHA256withRSA", provider)).build();
        assertThat(request.verifySignature()).isTrue();
        assertThat(key.exportAttempts.get()).isZero();
        assertThat(provider.signatures.get()).isEqualTo(1);
        assertThat(Security.getProviders()).containsExactly(before);
        assertThat(Security.getProvider(provider.getName())).isNull();
    }

    @Test
    void keyPairRouteAcceptsAlgorithmOverrideAndReplacesExplicitSigner() throws Exception {
        PkiSigner obsolete = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] content) { throw new AssertionError("obsolete signer called"); }
        };
        CsrRequest request = PkiCsr.create().subject("CN=Replacement").signer(EC.getPublic(), obsolete)
                .keyPair(RSA).signatureAlgorithm("SHA384withRSA").build();
        var bc = new PKCS10CertificationRequest(request.toDer());
        assertThat(bc.getSignatureAlgorithm().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        assertThat(request.getPublicKey().getEncoded()).isEqualTo(RSA.getPublic().getEncoded());
        CsrRequest other = PkiCsr.create().subject("CN=Other").keyPair(RSA)
                .signer(EC.getPublic(), PkiSigner.jca(EC.getPrivate())).build();
        assertThat(other.getPublicKey().getEncoded()).isEqualTo(EC.getPublic().getEncoded());
    }

    @Test
    void explicitSignerOwnsAlgorithmInEitherOrder() {
        PkiSigner signer = PkiSigner.jca(EC.getPrivate());
        assertThatThrownBy(() -> PkiCsr.create().signer(EC.getPublic(), signer).signatureAlgorithm("SHA384withECDSA"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiCsr.create().signatureAlgorithm("SHA384withECDSA").signer(EC.getPublic(), signer))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void missingRequiredValuesAndContradictoryConstraintsFailBeforeSigning() {
        AtomicInteger calls = new AtomicInteger();
        PkiSigner signer = countingSigner(calls);
        assertThatThrownBy(() -> PkiCsr.create().signer(EC.getPublic(), signer).build())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("subject");
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=No key").build())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("keyPair or signer");
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=Conflict").signer(EC.getPublic(), signer)
                .pathLength(0).isCA(false).build()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiCsr.create().pathLength(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThat(calls.get()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dns", "email", "uri"})
    void nonAsciiOriginalSanInputFailsBeforeSigning(String type) {
        AtomicInteger calls = new AtomicInteger();
        var builder = PkiCsr.create().subject("CN=SAN").signer(EC.getPublic(), countingSigner(calls));
        switch (type) {
            case "dns" -> builder.san(s -> s.dns("exämple.test"));
            case "email" -> builder.san(s -> s.email("usér@example.test"));
            default -> builder.san(s -> s.uri("https://example.test/café"));
        }
        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ASCII");
        assertThat(calls.get()).isZero();
    }

    @Test
    void duplicateRequestedExtensionOidsFailBeforeSigning() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CsrExtension custom = new CsrExtension("1.2.3.4", false, new DERUTF8String("value").getEncoded("DER"));
        assertThatThrownBy(() -> PkiCsr.create().extension(custom).extension(custom))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Duplicate");
        CsrExtension constraints = new CsrExtension(Extension.basicConstraints.getId(), true,
                new BasicConstraints(true).getEncoded("DER"));
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=Duplicate").signer(EC.getPublic(), countingSigner(calls))
                .extension(constraints).isCA(false).build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Duplicate");
        assertThat(calls.get()).isZero();
    }

    @Test
    void customExtensionCreationRequiresExactlyOneCanonicalDerValue() {
        assertThatThrownBy(() -> PkiCsr.create().extension(new CsrExtension("1.2.3.4", false, new byte[0])))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiCsr.create().extension(
                new CsrExtension("1.2.3.4", false, new byte[]{5, 0, 5, 0})))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiCsr.create().extension(
                new CsrExtension("1.2.3.4", false, new byte[]{4, (byte) 0x81, 1, 1})))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSignerForAnotherKeyCannotReturnASuccessfulRequest() {
        KeyPair wrong = PkiKeys.ec(Curve.P_256);
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=Mismatch")
                .signer(EC.getPublic(), PkiSigner.jca(wrong.getPrivate())).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=Mismatch")
                .keyPair(new KeyPair(EC.getPublic(), wrong.getPrivate())).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void checkedBackendFailureIsPreserved() {
        GeneralSecurityException failure = new GeneralSecurityException("backend unavailable");
        PkiSigner signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException { throw failure; }
        };
        assertThatThrownBy(() -> PkiCsr.create().subject("CN=Failure").signer(EC.getPublic(), signer).build())
                .isInstanceOf(IllegalStateException.class).hasCause(failure);
    }

    private static PkiSigner countingSigner(AtomicInteger calls) {
        return new PkiSigner() {
            @Override public String signatureAlgorithm() { return "SHA256withECDSA"; }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException {
                calls.incrementAndGet();
                return PkiSigner.jca(EC.getPrivate()).sign(content);
            }
        };
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
            super("EasyPkiCsrOpaqueTest", "1.0", "Synthetic CSR key-handle provider");
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
        @Override protected boolean engineVerify(byte[] signature) throws SignatureException { return delegate.verify(signature); }
        @Override protected void engineSetParameter(String parameter, Object value) { throw new UnsupportedOperationException(); }
        @Override protected Object engineGetParameter(String parameter) { throw new UnsupportedOperationException(); }
    }
}
