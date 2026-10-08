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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CsrRequestTest {
    private static final KeyPair RSA = keyPair("RSA");
    private static final KeyPair OTHER_RSA = keyPair("RSA");
    private static final KeyPair EC = keyPair("EC");
    private static final KeyPair OTHER_EC = keyPair("EC");
    private static final KeyPair ED = keyPair("Ed25519");
    private static final KeyPair OTHER_ED = keyPair("Ed25519");
    private static final String UNKNOWN_OID = "1.3.6.1.4.1.55555.1";

    @ParameterizedTest
    @ValueSource(strings = {"SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA512withECDSA", "Ed25519", "PSS", "PSS-MIXED"})
    void verifiesIndependentJcaSignaturesAndRejectsTamperingAndWrongKeys(String algorithm) throws Exception {
        KeyPair keys = keys(algorithm, false);
        var providers = Security.getProviders();
        byte[] encoded = request(algorithm, keys, keys.getPublic(), new DERSet());
        CsrRequest request = CsrRequest.fromDer(encoded);
        assertThat(request.verifySignature()).isTrue();
        assertThatCode(request::requireValidSignature).doesNotThrowAnyException();
        assertThat(request.getSubject()).isEqualTo(new X500Principal(new X500Name("CN=Requester,O=Example").getEncoded()));
        assertThat(request.getPublicKey().getEncoded()).isEqualTo(keys.getPublic().getEncoded());
        assertThat(Security.getProviders()).containsExactly(providers);

        ASN1Sequence raw = ASN1Sequence.getInstance(encoded);
        byte[] signature = org.bouncycastle.asn1.ASN1BitString.getInstance(raw.getObjectAt(2)).getOctets();
        signature[signature.length - 1] ^= 1;
        CsrRequest damagedSignature = CsrRequest.fromDer(new DERSequence(new ASN1Encodable[] {
                raw.getObjectAt(0), raw.getObjectAt(1), new DERBitString(signature)}).getEncoded());
        assertThat(damagedSignature.verifySignature()).isFalse();
        assertThatThrownBy(damagedSignature::requireValidSignature).isInstanceOf(IllegalArgumentException.class);

        ASN1Sequence info = ASN1Sequence.getInstance(raw.getObjectAt(0));
        byte[] changedSubject = new DERSequence(new ASN1Encodable[] {
                new DERSequence(new ASN1Encodable[] {info.getObjectAt(0), new X500Name("CN=Changed"),
                        info.getObjectAt(2), info.getObjectAt(3)}), raw.getObjectAt(1), raw.getObjectAt(2)}).getEncoded();
        assertThat(CsrRequest.fromDer(changedSubject).verifySignature()).isFalse();
        byte[] wrongKey = request(algorithm, keys, keys(algorithm, true).getPublic(), new DERSet());
        assertThat(CsrRequest.fromDer(wrongKey).verifySignature()).isFalse();
    }

    @Test
    void roundTripsUnknownAttributesAndRequestedExtensionsWithDefensiveCopies() throws Exception {
        byte[] extensionValue = new DERUTF8String("opaque value").getEncoded();
        Attribute unknown = new Attribute(new ASN1ObjectIdentifier(UNKNOWN_OID),
                new DERSet(new ASN1Encodable[] {new DERUTF8String("first"), new DERUTF8String("second")}));
        Attribute extensionRequest = extensionAttribute(new Extension(new ASN1ObjectIdentifier(UNKNOWN_OID), true, extensionValue));
        byte[] encoded = request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet(new ASN1Encodable[] {unknown, extensionRequest}));
        byte[] original = encoded.clone();
        CsrRequest request = CsrRequest.fromDer(encoded);
        encoded[0] = 0;
        byte[] exported = request.toDer();
        exported[0] = 0;
        assertThat(request.toDer()).isEqualTo(original);
        assertThat(CsrRequest.fromPem(request.toPem()).toDer()).isEqualTo(original);
        assertThat(request.getAttributes()).hasSize(1);
        CsrAttribute attribute = request.getAttributes().get(0);
        assertThat(attribute.getOid()).isEqualTo(UNKNOWN_OID);
        byte[] attributeValue = attribute.getValues().get(0);
        byte first = attributeValue[0];
        attributeValue[0] ^= 1;
        assertThat(attribute.getValues().get(0)[0]).isEqualTo(first);
        assertThatThrownBy(() -> attribute.getValues().add(new byte[0])).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> request.getAttributes().clear()).isInstanceOf(UnsupportedOperationException.class);
        CsrExtension extension = request.getRequestedExtensions().get(0);
        assertThat(extension.getOid()).isEqualTo(UNKNOWN_OID);
        assertThat(extension.isCritical()).isTrue();
        byte[] returnedValue = extension.getValue();
        returnedValue[0] = 0;
        assertThat(extension.getValue()).isEqualTo(extensionValue);
        assertThatThrownBy(() -> request.getRequestedExtensions().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void valueObjectsCopyTheirInputsAndValidateAttributeDer() throws Exception {
        byte[] value = new DERUTF8String("value").getEncoded();
        byte[] original = value.clone();
        List<byte[]> values = new ArrayList<>(List.of(value));
        CsrExtension extension = new CsrExtension(UNKNOWN_OID, false, value);
        CsrAttribute attribute = new CsrAttribute(UNKNOWN_OID, values);
        values.clear();
        value[0] = 0;
        assertThat(extension.getValue()).isEqualTo(original);
        assertThat(attribute.getValues()).hasSize(1);
        assertThat(attribute.getValues().get(0)).isEqualTo(original);
        assertThatThrownBy(() -> new CsrAttribute(UNKNOWN_OID, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CsrAttribute(UNKNOWN_OID, List.of(new byte[] {1, 2})))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CsrExtension("invalid", false, original)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsStandardAndLegacyPemLabelsAndFileFormats(@TempDir Path directory) throws Exception {
        CsrRequest request = CsrRequest.fromDer(request("Ed25519", ED, ED.getPublic(), new DERSet()));
        String pem = request.toPem();
        assertThat(CsrRequest.fromPem(" \n" + pem + "\t").toDer()).isEqualTo(request.toDer());
        assertThat(CsrRequest.fromPem(pem.replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")).toDer())
                .isEqualTo(request.toDer());
        assertThat(CsrRequest.fromPem(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))).toDer())
                .isEqualTo(request.toDer());
        Path derFile = directory.resolve("request.der");
        Path pemFile = directory.resolve("request.pem");
        Files.write(derFile, request.toDer());
        Files.writeString(pemFile, pem);
        assertThat(CsrRequest.fromFile(derFile).toDer()).isEqualTo(request.toDer());
        assertThat(CsrRequest.fromFile(pemFile).toDer()).isEqualTo(request.toDer());
        assertThatThrownBy(() -> CsrRequest.fromFile(directory.resolve("missing"))).isInstanceOf(UncheckedIOException.class);
    }

    @Test
    void rejectsPemWithOtherLabelsAdditionalObjectsAndSurroundingText() throws Exception {
        String pem = CsrRequest.fromDer(request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet())).toPem();
        for (String invalid : List.of("", "not PEM", pem.replace("CERTIFICATE REQUEST", "CERTIFICATE"),
                pem + pem, "text\n" + pem, pem + "text", pem.replace("-----END CERTIFICATE REQUEST-----", ""),
                pem.replace("-----END CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----"))) {
            assertThatThrownBy(() -> CsrRequest.fromPem(invalid)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void closesReaderAndReportsIoFailures() {
        boolean[] closed = {false};
        Reader reader = new Reader() {
            @Override public int read(char[] target, int offset, int length) throws IOException { throw new IOException("read failure"); }
            @Override public void close() { closed[0] = true; }
        };
        assertThatThrownBy(() -> CsrRequest.fromPem(reader)).isInstanceOf(UncheckedIOException.class);
        assertThat(closed[0]).isTrue();
    }

    @Test
    void rejectsNonDerAndTrailingData() throws Exception {
        byte[] valid = request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet());
        ASN1Sequence raw = ASN1Sequence.getInstance(valid);
        byte[] ber = new BERSequence(new ASN1Encodable[] {raw.getObjectAt(0), raw.getObjectAt(1), raw.getObjectAt(2)}).getEncoded();
        byte[] doubled = new byte[valid.length * 2];
        System.arraycopy(valid, 0, doubled, 0, valid.length);
        System.arraycopy(valid, 0, doubled, valid.length, valid.length);
        for (byte[] invalid : List.of(new byte[0], new byte[] {1, 2, 3}, Arrays.copyOf(valid, valid.length - 1),
                Arrays.copyOf(valid, valid.length + 1), doubled, ber, DERNull.INSTANCE.getEncoded())) {
            assertThatThrownBy(() -> CsrRequest.fromDer(invalid)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void rejectsWrongVersionExtraFieldsBadAttributeTagAndUnalignedBitStrings() throws Exception {
        ASN1Sequence raw = ASN1Sequence.getInstance(request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet()));
        ASN1Sequence info = ASN1Sequence.getInstance(raw.getObjectAt(0));
        List<ASN1Sequence> invalidInfo = List.of(
                new DERSequence(new ASN1Encodable[] {new ASN1Integer(1), info.getObjectAt(1), info.getObjectAt(2), info.getObjectAt(3)}),
                new DERSequence(new ASN1Encodable[] {info.getObjectAt(0), info.getObjectAt(1), info.getObjectAt(2)}),
                new DERSequence(new ASN1Encodable[] {info.getObjectAt(0), info.getObjectAt(1), info.getObjectAt(2), info.getObjectAt(3), DERNull.INSTANCE}),
                new DERSequence(new ASN1Encodable[] {info.getObjectAt(0), info.getObjectAt(1), info.getObjectAt(2), new DERTaggedObject(false, 1, new DERSet())}),
                new DERSequence(new ASN1Encodable[] {info.getObjectAt(0), info.getObjectAt(1), info.getObjectAt(2), new DERTaggedObject(true, 0, new DERSet())}));
        for (ASN1Sequence invalid : invalidInfo) {
            byte[] encoded = new DERSequence(new ASN1Encodable[] {invalid, raw.getObjectAt(1), raw.getObjectAt(2)}).getEncoded();
            assertThatThrownBy(() -> CsrRequest.fromDer(encoded)).isInstanceOf(IllegalArgumentException.class);
        }
        for (DERBitString bits : List.of(new DERBitString(new byte[] {0}, 1), new DERBitString(new byte[0]))) {
            byte[] encoded = new DERSequence(new ASN1Encodable[] {info, raw.getObjectAt(1), bits}).getEncoded();
            assertThatThrownBy(() -> CsrRequest.fromDer(encoded)).isInstanceOf(IllegalArgumentException.class);
        }
        byte[] tooMany = new DERSequence(new ASN1Encodable[] {info, raw.getObjectAt(1), raw.getObjectAt(2), DERNull.INSTANCE}).getEncoded();
        assertThatThrownBy(() -> CsrRequest.fromDer(tooMany)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsDuplicateExtensionRequestAttributesAndValuesAndDuplicateExtensionOids() throws Exception {
        Extension extension = new Extension(new ASN1ObjectIdentifier(UNKNOWN_OID), false, DERNull.INSTANCE.getEncoded());
        Attribute valid = extensionAttribute(extension);
        List<DERSet> invalidSets = List.of(
                new DERSet(new ASN1Encodable[] {valid, valid}),
                new DERSet(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        new DERSet(new ASN1Encodable[] {new DERSequence(extension), new DERSequence(extension)}))),
                new DERSet(extensionAttribute(extension, extension)),
                new DERSet(extensionAttribute()),
                new DERSet(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet())),
                new DERSet(new Attribute(new ASN1ObjectIdentifier(UNKNOWN_OID), new DERSet())),
                new DERSet(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(DERNull.INSTANCE))));
        for (DERSet attributes : invalidSets) {
            byte[] encoded = request("SHA256withRSA", RSA, RSA.getPublic(), attributes);
            assertThatThrownBy(() -> CsrRequest.fromDer(encoded)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void preservesInvalidUnknownExtensionPayloadForInspection() throws Exception {
        byte[] payload = {1, 2, 3};
        byte[] encoded = request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet(extensionAttribute(
                new Extension(new ASN1ObjectIdentifier(UNKNOWN_OID), false, payload))));
        assertThat(CsrRequest.fromDer(encoded).getRequestedExtensions().get(0).getValue()).isEqualTo(payload);
    }

    @Test
    void unsupportedAlgorithmsAndInvalidParametersAreInspectableButNeverVerify() throws Exception {
        ASN1Sequence rsa = ASN1Sequence.getInstance(request("SHA256withRSA", RSA, RSA.getPublic(), new DERSet()));
        List<AlgorithmIdentifier> invalid = List.of(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier(UNKNOWN_OID)),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, new ASN1Integer(4)),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, DERNull.INSTANCE));
        for (AlgorithmIdentifier algorithm : invalid) {
            CsrRequest parsed = CsrRequest.fromDer(new DERSequence(new ASN1Encodable[] {
                    rsa.getObjectAt(0), algorithm, rsa.getObjectAt(2)}).getEncoded());
            assertThat(parsed.verifySignature()).isFalse();
        }
        ASN1Sequence ed = ASN1Sequence.getInstance(request("Ed25519", ED, ED.getPublic(), new DERSet()));
        assertThat(CsrRequest.fromDer(new DERSequence(new ASN1Encodable[] {ed.getObjectAt(0),
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.101.112"), DERNull.INSTANCE), ed.getObjectAt(2)})
                .getEncoded()).verifySignature()).isFalse();
    }

    @Test
    void doesNotSilentlyIgnoreChangedPssMgfOrSaltParameters() throws Exception {
        ASN1Sequence raw = ASN1Sequence.getInstance(request("PSS-MIXED", RSA, RSA.getPublic(), new DERSet()));
        for (AlgorithmIdentifier changed : List.of(pssAlgorithm("SHA-256", 32), pssAlgorithm("SHA-384", 31))) {
            byte[] encoded = new DERSequence(new ASN1Encodable[] {raw.getObjectAt(0), changed, raw.getObjectAt(2)}).getEncoded();
            assertThat(CsrRequest.fromDer(encoded).verifySignature()).isFalse();
        }
    }

    @Test
    void malformedPssParameterFieldsFailWithoutThrowing() throws Exception {
        ASN1Sequence raw = ASN1Sequence.getInstance(request("PSS", RSA, RSA.getPublic(), new DERSet()));
        AlgorithmIdentifier hash = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE);
        AlgorithmIdentifier mgf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hash);
        List<ASN1Encodable> invalidParameters = List.of(
                new RSASSAPSSparams(hash, mgf, new ASN1Integer(-1), new ASN1Integer(1)),
                new RSASSAPSSparams(hash, mgf, new ASN1Integer(BigInteger.ONE.shiftLeft(64)), new ASN1Integer(1)),
                new RSASSAPSSparams(hash, mgf, new ASN1Integer(32), new ASN1Integer(2)),
                new RSASSAPSSparams(hash, new AlgorithmIdentifier(new ASN1ObjectIdentifier(UNKNOWN_OID), hash),
                        new ASN1Integer(32), new ASN1Integer(1)),
                new DERSequence(new ASN1Encodable[] {new DERTaggedObject(true, 2, new ASN1Integer(32)),
                        new DERTaggedObject(true, 2, new ASN1Integer(32))}),
                new DERSequence(new ASN1Encodable[] {new DERTaggedObject(true, 2, new ASN1Integer(32)),
                        new DERTaggedObject(true, 0, hash)}),
                new DERSequence(new DERTaggedObject(false, 2, new ASN1Integer(32))));
        for (ASN1Encodable parameters : invalidParameters) {
            CsrRequest parsed = CsrRequest.fromDer(new DERSequence(new ASN1Encodable[] {
                    raw.getObjectAt(0), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, parameters),
                    raw.getObjectAt(2)}).getEncoded());
            assertThat(parsed.verifySignature()).isFalse();
        }
    }

    private static Attribute extensionAttribute(Extension... extensions) {
        return new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(new DERSequence(extensions)));
    }

    private static byte[] request(String algorithm, KeyPair signingKeys, PublicKey publicKey, DERSet attributes) throws Exception {
        CertificationRequestInfo info = new CertificationRequestInfo(new X500Name("CN=Requester,O=Example"),
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), attributes);
        AlgorithmIdentifier identifier;
        Signature signer;
        if (algorithm.startsWith("PSS")) {
            String mgfHash = algorithm.equals("PSS-MIXED") ? "SHA-384" : "SHA-256";
            signer = Signature.getInstance("RSASSA-PSS");
            signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec(mgfHash), 32, 1));
            identifier = pssAlgorithm(mgfHash, 32);
        } else {
            signer = Signature.getInstance(algorithm);
            identifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        }
        signer.initSign(signingKeys.getPrivate());
        signer.update(info.getEncoded());
        return new DERSequence(new ASN1Encodable[] {info, identifier, new DERBitString(signer.sign())}).getEncoded();
    }

    private static AlgorithmIdentifier pssAlgorithm(String mgfHash, int saltLength) {
        AlgorithmIdentifier hash = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE);
        AlgorithmIdentifier mgf = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
                mgfHash.equals("SHA-384") ? "2.16.840.1.101.3.4.2.2" : "2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE);
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                new RSASSAPSSparams(hash, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgf),
                        new ASN1Integer(saltLength), new ASN1Integer(1)));
    }

    private static KeyPair keys(String algorithm, boolean other) {
        if (algorithm.equals("Ed25519")) return other ? OTHER_ED : ED;
        if (algorithm.endsWith("ECDSA")) return other ? OTHER_EC : EC;
        return other ? OTHER_RSA : RSA;
    }

    private static KeyPair keyPair(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            if (algorithm.equals("RSA")) generator.initialize(2048);
            if (algorithm.equals("EC")) generator.initialize(256);
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
