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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class CsrIssuancePolicyTest {
    private static final KeyPair CA_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair RSA = PkiKeys.rsa(2048);
    private static final KeyPair EC = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ED = PkiKeys.ed25519();
    private static final Instant CA_START = Instant.parse("2020-01-01T00:00:00Z");
    private static final Instant CA_END = Instant.parse("2040-01-01T00:00:00Z");
    private static final Instant START = Instant.parse("2030-01-01T00:00:00Z");
    private static final Instant END = Instant.parse("2031-01-01T00:00:00Z");
    private static final String UNKNOWN_OID = "1.3.6.1.4.1.55555.33";

    @Test
    void validProofAloneDoesNotAuthorizeSubjectOrSans() throws Exception {
        var request = csr(ED, "Ed25519", "CN=Client");
        var issuer = issuer("CN=Policy Root", 2);
        assertThat(request.verifySignature()).isTrue();
        reject(issuer, () -> issue(request,
                CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT).build(), issuer).build());

        var server = csr(ED, "Ed25519", "CN=Server", dns("service.example.test"));
        var subjectOnly = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> true).build();
        reject(issuer, () -> issue(server, subjectOnly, issuer).build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC", "Ed25519"})
    void approvedTlsRequestUsesItsAuthorizedSubjectKeyAndNames(String algorithm) throws Exception {
        KeyPair keys = keys(algorithm);
        String signature = algorithm.equals("RSA") ? "SHA384withRSA"
                : algorithm.equals("EC") ? "SHA512withECDSA" : "Ed25519";
        X500Principal subject = new X500Principal("CN=Service\\+Worker,O=Example");
        var request = csr(keys, signature, subject.getName(),
                extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "Api.Example.test"),
                        new GeneralName(GeneralName.iPAddress, "192.0.2.10")})));
        List<SubjectAlternativeName> approved = new ArrayList<>();
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject::equals).allowSan(name -> { approved.add(name); return true; }).build();
        var issuer = issuer("CN=Policy Root", 2);
        X509Certificate certificate = issue(request, policy, issuer).serialNumber(BigInteger.valueOf(42)).build();
        certificate.verify(issuer.identity().getCertificate().getPublicKey());
        assertThat(certificate.getSubjectX500Principal()).isEqualTo(subject);
        assertThat(certificate.getPublicKey().getEncoded()).isEqualTo(request.getPublicKey().getEncoded());
        assertThat(certificate.getSerialNumber()).isEqualTo(BigInteger.valueOf(42));
        assertThat(certificate.getNotBefore().toInstant()).isEqualTo(START);
        assertThat(certificate.getNotAfter().toInstant()).isEqualTo(END);
        assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
        assertThat(certificate.getExtendedKeyUsage()).containsExactly(KeyPurposeId.id_kp_serverAuth.getId());
        assertThat(approved).containsExactly(
                new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "Api.Example.test"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.IP_ADDRESS, "192.0.2.10"));
        assertThat(certificate.getSubjectAlternativeNames()).containsExactly(
                List.of(2, "Api.Example.test"), List.of(7, "192.0.2.10"));
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @Test
    void oneUnauthorizedSanRejectsTheEntireRequest() throws Exception {
        var request = csr(ED, "Ed25519", "CN=Server",
                extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "allowed.example.test"),
                        new GeneralName(GeneralName.dNSName, "forbidden.example.test")})));
        List<String> evaluated = new ArrayList<>();
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER).allowSubject(subject -> true)
                .allowSan(name -> { evaluated.add(name.value()); return name.value().equals("allowed.example.test"); })
                .build();
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy, issuer).build());
        assertThat(evaluated).containsExactly("allowed.example.test", "forbidden.example.test");
    }

    @Test
    void invalidSignatureInvokesNeitherAuthorizersNorIssuerSigner() throws Exception {
        var valid = csr(ED, "Ed25519", "CN=Server", dns("service.example.test"));
        ASN1Sequence raw = ASN1Sequence.getInstance(valid.toDer());
        byte[] signature = ASN1BitString.getInstance(raw.getObjectAt(2)).getOctets();
        signature[0] ^= 1;
        var damaged = CsrRequest.fromDer(new DERSequence(new ASN1Encodable[]{
                raw.getObjectAt(0), raw.getObjectAt(1), new DERBitString(signature)}).getEncoded());
        var authorizations = new AtomicInteger();
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> { authorizations.incrementAndGet(); return true; })
                .allowSan(name -> { authorizations.incrementAndGet(); return true; })
                .allowPublicKey(key -> { authorizations.incrementAndGet(); return true; }).build();
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(damaged, policy, issuer).build());
        assertThat(authorizations.get()).isZero();
    }

    @Test
    void profileOwnsExtensionCriticalityRatherThanCopyingTheRequest() throws Exception {
        var request = csr(ED, "Ed25519", "",
                dns("service.example.test"),
                extension(Extension.basicConstraints, false, new BasicConstraints(false)),
                extension(Extension.keyUsage, false,
                        new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature)),
                extension(Extension.extendedKeyUsage, true,
                        new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)));
        var emptySubjectApproved = new AtomicBoolean();
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> { emptySubjectApproved.set(subject.getName().isEmpty()); return true; })
                .allowSan(name -> true).build();
        var issuer = issuer("CN=Policy Root", 2);
        X509Certificate certificate = issue(request, policy, issuer).build();
        assertThat(emptySubjectApproved.get()).isTrue();
        assertThat(certificate.getSubjectX500Principal().getName()).isEmpty();
        assertThat(certificate.getCriticalExtensionOIDs()).contains(
                Extension.basicConstraints.getId(), Extension.keyUsage.getId(), Extension.subjectAlternativeName.getId());
        assertThat(certificate.getNonCriticalExtensionOIDs()).contains(Extension.extendedKeyUsage.getId());
        assertThat(certificate.getSigAlgOID()).isEqualTo(issuer.identity().getCertificate().getSigAlgOID());
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @Test
    void clientUriIdentityDoesNotInventServerNamesOrUsage() throws Exception {
        var request = csr(EC, "SHA256withECDSA", "",
                extension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "urn:example:worker:7"))));
        var issuer = issuer("CN=Policy Root", 2);
        X509Certificate certificate = issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build();
        assertThat(certificate.getExtendedKeyUsage()).containsExactly(KeyPurposeId.id_kp_clientAuth.getId());
        assertThat(certificate.getSubjectAlternativeNames()).containsExactly(List.of(6, "urn:example:worker:7"));
        assertThat(certificate.getKeyUsage()[0]).isTrue();
        assertThat(certificate.getKeyUsage()[2]).isFalse();
        assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"basic-constraints", "key-cert-sign", "crl-sign", "ca-false-with-cert-sign", "wrong-eku"})
    void tlsRequestsCannotAcquireCaPrivilegesOrOtherPurposes(String mode) throws Exception {
        List<Extension> extensions = new ArrayList<>();
        switch (mode) {
            case "basic-constraints" -> extensions.add(extension(Extension.basicConstraints, false, new BasicConstraints(true)));
            case "key-cert-sign", "ca-false-with-cert-sign" -> extensions.add(extension(Extension.keyUsage, false,
                    new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign)));
            case "crl-sign" -> extensions.add(extension(Extension.keyUsage, false,
                    new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.cRLSign)));
            case "wrong-eku" -> extensions.add(extension(Extension.extendedKeyUsage, false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)));
            default -> throw new AssertionError(mode);
        }
        if (mode.equals("ca-false-with-cert-sign")) {
            extensions.add(extension(Extension.basicConstraints, false, new BasicConstraints(false)));
        }
        var request = csr(ED, "Ed25519", "CN=Client", extensions.toArray(Extension[]::new));
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build());
    }

    @Test
    void intermediateCaNeedsExplicitPolicyGrantEvenWithValidCaRequest() throws Exception {
        var request = csr(EC, "SHA256withECDSA", "CN=Intermediate",
                extension(Extension.basicConstraints, true, new BasicConstraints(0)));
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, CsrIssuancePolicy.forProfile(CertificateProfile.INTERMEDIATE_CA)
                .allowSubject(subject -> true).build(), issuer).build());
        assertThatThrownBy(() -> CsrIssuancePolicy.forProfile(CertificateProfile.ROOT_CA).build())
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-extension", "ca-no-path", "finite-zero", "finite-one"})
    void explicitIntermediateGrantBoundsRequestedAndAbsentPathLengths(String mode) throws Exception {
        Extension[] requested = switch (mode) {
            case "no-extension" -> new Extension[0];
            case "ca-no-path" -> new Extension[]{extension(Extension.basicConstraints, false, new BasicConstraints(true))};
            case "finite-zero" -> new Extension[]{extension(Extension.basicConstraints, true, new BasicConstraints(0))};
            default -> new Extension[]{extension(Extension.basicConstraints, true, new BasicConstraints(1))};
        };
        var request = csr(EC, "SHA256withECDSA", "CN=Intermediate", requested);
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.INTERMEDIATE_CA)
                .allowSubject(subject -> true).allowCaRequests(1).build();
        var issuer = issuer("CN=Policy Root", 2);
        X509Certificate certificate = issue(request, policy, issuer).build();
        assertThat(certificate.getBasicConstraints()).isEqualTo(mode.equals("finite-zero") ? 0 : 1);
        assertThat(certificate.getKeyUsage()[5]).isTrue();
        assertThat(certificate.getKeyUsage()[6]).isTrue();
        assertThat(certificate.getExtendedKeyUsage()).isNull();
        certificate.verify(issuer.identity().getCertificate().getPublicKey());
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"false-ca", "excess-path", "huge-path", "eku"})
    void intermediateRequestConflictsCannotBeSilentlyDropped(String mode) throws Exception {
        Extension requested = switch (mode) {
            case "false-ca" -> extension(Extension.basicConstraints, true, new BasicConstraints(false));
            case "excess-path" -> extension(Extension.basicConstraints, true, new BasicConstraints(2));
            case "huge-path" -> extension(Extension.basicConstraints, true, new DERSequence(new ASN1Encodable[]{
                    ASN1Boolean.TRUE, new ASN1Integer(BigInteger.ONE.shiftLeft(80))}));
            default -> extension(Extension.extendedKeyUsage, false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        };
        var request = csr(EC, "SHA256withECDSA", "CN=Intermediate", requested);
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, caPolicy(1), issuer).build());
    }

    @Test
    void policyGrantDoesNotOverrideIssuerPathOrValidityConstraints() throws Exception {
        var request = csr(EC, "SHA256withECDSA", "CN=Intermediate");
        var exhausted = issuer("CN=Exhausted", 0);
        reject(exhausted, () -> issue(request, caPolicy(0), exhausted).build());
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, caPolicy(0), issuer).validUntil(CA_END.plusSeconds(1)).build());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unknownExtensionsRejectRegardlessOfCriticality(boolean critical) throws Exception {
        var request = csr(ED, "Ed25519", "CN=Client",
                extension(new ASN1ObjectIdentifier(UNKNOWN_OID), critical, DERNull.INSTANCE));
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build());
    }

    @Test
    void unknownAttributesAreInspectableButNotAuthorizedForIssuance() throws Exception {
        var request = request(ED, "Ed25519", "CN=Client", new DERSet(new Attribute(
                new ASN1ObjectIdentifier(UNKNOWN_OID), new DERSet(new DERUTF8String("opaque attribute")))), null);
        assertThat(request.verifySignature()).isTrue();
        assertThat(request.getAttributes()).hasSize(1);
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build());
    }

    @ParameterizedTest(name = "Reject malformed {0}")
    @MethodSource("malformedExtensions")
    void signedMalformedKnownExtensionsRejectBeforeIssuerSigning(String description,
                                                                 CertificateProfile profile, Extension extension)
            throws Exception {
        var request = csr(ED, "Ed25519", "CN=Subject", extension);
        assertThat(request.verifySignature()).as(description).isTrue();
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request,
                profile == CertificateProfile.INTERMEDIATE_CA ? caPolicy(1) : policy(profile), issuer).build());
    }

    static Stream<Arguments> malformedExtensions() throws Exception {
        CertificateProfile tls = CertificateProfile.TLS_CLIENT;
        CertificateProfile ca = CertificateProfile.INTERMEDIATE_CA;
        return Stream.of(
                Arguments.of("BC trailing field", ca, extension(Extension.basicConstraints, true,
                        new DERSequence(new ASN1Encodable[]{ASN1Boolean.TRUE, new ASN1Integer(0), new ASN1Integer(7)}))),
                Arguments.of("BC negative path", ca, extension(Extension.basicConstraints, true,
                        new DERSequence(new ASN1Encodable[]{ASN1Boolean.TRUE, new ASN1Integer(-1)}))),
                Arguments.of("BC path without CA", tls, extension(Extension.basicConstraints, true,
                        new DERSequence(new ASN1Integer(0)))),
                Arguments.of("BC false with path", tls, extension(Extension.basicConstraints, true,
                        new DERSequence(new ASN1Encodable[]{ASN1Boolean.FALSE, new ASN1Integer(0)}))),
                Arguments.of("BC explicit false default", tls, new Extension(Extension.basicConstraints, true,
                        new byte[]{0x30, 0x03, 0x01, 0x01, 0x00})),
                Arguments.of("BC BER inner value", ca, new Extension(Extension.basicConstraints, true,
                        new BERSequence(ASN1Boolean.TRUE).getEncoded())),
                Arguments.of("KU unknown ninth bit", tls, extension(Extension.keyUsage, true,
                        new DERBitString(new byte[]{(byte) 0x80, 0x40}, 6))),
                Arguments.of("KU unknown fifth byte", tls, extension(Extension.keyUsage, true,
                        new DERBitString(new byte[]{(byte) 0x80, 0, 0, 0, 1}))),
                Arguments.of("KU all zero", tls, extension(Extension.keyUsage, true, new DERBitString(new byte[]{0}))),
                Arguments.of("KU empty", tls, extension(Extension.keyUsage, true, new DERBitString(new byte[0]))),
                Arguments.of("KU nonminimal named bits", tls, new Extension(Extension.keyUsage, true,
                        new byte[]{0x03, 0x03, 0x00, (byte) 0x80, 0x00})),
                Arguments.of("EKU empty", tls, extension(Extension.extendedKeyUsage, false, new DERSequence())),
                Arguments.of("EKU non-OID", tls, extension(Extension.extendedKeyUsage, false,
                        new DERSequence(new DERUTF8String("not an OID")))),
                Arguments.of("SAN empty", tls, extension(Extension.subjectAlternativeName, false, new DERSequence())),
                Arguments.of("SAN malformed content", tls, extension(Extension.subjectAlternativeName, false,
                        new DERSequence(new DERUTF8String("not a GeneralName")))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA1withRSA", "SHA224withECDSA"})
    void mathematicallyValidWeakSignatureIsNotAnIssuanceAuthorization(String signature) throws Exception {
        var request = csr(signature.endsWith("RSA") ? RSA : EC, signature, "CN=Client");
        assertThat(request.verifySignature()).isTrue();
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void pssPolicyChecksBothMessageAndMaskDigest(boolean weakMessage) throws Exception {
        PSSParameterSpec parameters = new PSSParameterSpec(weakMessage ? "SHA-1" : "SHA-256", "MGF1",
                weakMessage ? MGF1ParameterSpec.SHA256 : MGF1ParameterSpec.SHA1, 20, 1);
        var request = request(RSA, "RSASSA-PSS", "CN=Client", new DERSet(), parameters);
        assertThat(request.verifySignature()).isTrue();
        var issuer = issuer("CN=Policy Root", 2);
        reject(issuer, () -> issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build());
    }

    @Test
    void strongPssWithDifferentMessageAndMaskDigestsCanBeIssued() throws Exception {
        PSSParameterSpec parameters = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384, 24, 1);
        var request = request(RSA, "RSASSA-PSS", "CN=Client", new DERSet(), parameters);
        var issuer = issuer("CN=Policy Root", 2);
        X509Certificate certificate = issue(request, policy(CertificateProfile.TLS_CLIENT), issuer).build();
        certificate.verify(issuer.identity().getCertificate().getPublicKey());
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @Test
    void customPublicKeyPredicateCanRestrictButCannotRelaxBaselineStrength() throws Exception {
        var issuer = issuer("CN=Policy Root", 2);
        var valid = csr(ED, "Ed25519", "CN=Client");
        var denyKeys = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT)
                .allowSubject(subject -> true).allowPublicKey(key -> false).build();
        reject(issuer, () -> issue(valid, denyKeys, issuer).build());
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        var weak = csr(generator.generateKeyPair(), "SHA256withRSA", "CN=Client");
        assertThat(weak.verifySignature()).isTrue();
        var allowAllKeys = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT)
                .allowSubject(subject -> true).allowPublicKey(key -> true).build();
        reject(issuer, () -> issue(weak, allowAllKeys, issuer).build());
    }

    @Test
    void authorizationIsEvaluatedAgainOnEveryBuild() throws Exception {
        var authorized = new AtomicBoolean(true);
        var request = csr(ED, "Ed25519", "CN=Client");
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT)
                .allowSubject(subject -> authorized.get()).build();
        var issuer = issuer("CN=Policy Root", 2);
        var builder = issue(request, policy, issuer);
        builder.build();
        assertThat(issuer.calls().get()).isEqualTo(1);
        authorized.set(false);
        assertThatThrownBy(builder::build).isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @Test
    void builtPolicyDoesNotChangeWhenItsBuilderIsReconfigured() throws Exception {
        var mutable = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT).allowSubject(subject -> true);
        var approved = mutable.build();
        mutable.allowSubject(subject -> false);
        var request = csr(ED, "Ed25519", "CN=Client");
        var issuer = issuer("CN=Policy Root", 2);
        issue(request, approved, issuer).build();
        assertThat(issuer.calls().get()).isEqualTo(1);
        assertThatThrownBy(() -> issue(request, mutable.build(), issuer).build())
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(issuer.calls().get()).isEqualTo(1);
    }

    @Test
    void callbackMutationAffectsOnlyTheNextBuildSnapshot() throws Exception {
        var first = issuer("CN=First Issuer", 2);
        var second = issuer("CN=Second Issuer", 2);
        var request = csr(ED, "Ed25519", "CN=Client");
        var reference = new AtomicReference<CsrCertificateBuilder>();
        var mutate = new AtomicBoolean(true);
        Instant later = END.plus(Duration.ofDays(30));
        var policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_CLIENT).allowSubject(subject -> {
            if (mutate.getAndSet(false)) reference.get().issuer(second.identity())
                    .serialNumber(BigInteger.valueOf(99)).validUntil(later);
            return true;
        }).build();
        var builder = issue(request, policy, first).serialNumber(BigInteger.valueOf(17));
        reference.set(builder);
        X509Certificate original = builder.build();
        assertThat(original.getIssuerX500Principal()).isEqualTo(first.identity().getCertificate().getSubjectX500Principal());
        assertThat(original.getSerialNumber()).isEqualTo(BigInteger.valueOf(17));
        assertThat(original.getNotAfter().toInstant()).isEqualTo(END);
        assertThat(first.calls().get()).isEqualTo(1);
        assertThat(second.calls().get()).isZero();
        X509Certificate changed = builder.build();
        assertThat(changed.getIssuerX500Principal()).isEqualTo(second.identity().getCertificate().getSubjectX500Principal());
        assertThat(changed.getSerialNumber()).isEqualTo(BigInteger.valueOf(99));
        assertThat(changed.getNotAfter().toInstant()).isEqualTo(later);
        assertThat(second.calls().get()).isEqualTo(1);
    }

    private static CsrIssuancePolicy policy(CertificateProfile profile) {
        return CsrIssuancePolicy.forProfile(profile).allowSubject(subject -> true).allowSan(name -> true).build();
    }

    private static CsrIssuancePolicy caPolicy(int maximum) {
        return CsrIssuancePolicy.forProfile(CertificateProfile.INTERMEDIATE_CA)
                .allowSubject(subject -> true).allowSan(name -> true).allowCaRequests(maximum).build();
    }

    private static CsrCertificateBuilder issue(CsrRequest request, CsrIssuancePolicy policy, CountedIssuer issuer) {
        return PkiCsr.issue(request, policy).issuer(issuer.identity()).validFrom(START).validUntil(END);
    }

    private static void reject(CountedIssuer issuer, Runnable operation) {
        assertThatThrownBy(operation::run).isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(issuer.calls().get()).as("denied issuance must not invoke the CA signer").isZero();
    }

    private static CountedIssuer issuer(String subject, int pathLength) {
        var certificate = PkiCertificate.rootCa().subject(subject).keyPair(CA_KEYS).pathLength(pathLength)
                .validFrom(CA_START).validUntil(CA_END).build();
        var calls = new AtomicInteger();
        PkiSigner delegate = PkiSigner.jca(CA_KEYS.getPrivate());
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return delegate.signatureAlgorithm(); }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException {
                calls.incrementAndGet();
                return delegate.sign(data);
            }
        };
        var identity = PkiIdentity.of(certificate, signer);
        assertThat(calls.get()).as("identity possession proof").isEqualTo(1);
        calls.set(0);
        return new CountedIssuer(identity, calls);
    }

    private static KeyPair keys(String algorithm) {
        return switch (algorithm) { case "RSA" -> RSA; case "EC" -> EC; default -> ED; };
    }

    private static Extension dns(String name) throws Exception {
        return extension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, name)));
    }

    private static Extension extension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) throws Exception {
        return new Extension(oid, critical, value.toASN1Primitive().getEncoded());
    }

    private static CsrRequest csr(KeyPair keys, String algorithm, String subject, Extension... extensions) throws Exception {
        DERSet attributes = extensions.length == 0 ? new DERSet() : new DERSet(new Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(new DERSequence(extensions))));
        return request(keys, algorithm, subject, attributes, null);
    }

    /** Fixtures use direct JCA proof signatures, independently of the fluent CSR creation path. */
    private static CsrRequest request(KeyPair keys, String algorithm, String subject, DERSet attributes,
                                      PSSParameterSpec pss) throws Exception {
        var info = new CertificationRequestInfo(X500Name.getInstance(new X500Principal(subject).getEncoded()),
                SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()), attributes);
        Signature signer = Signature.getInstance(algorithm);
        AlgorithmIdentifier identifier;
        if (pss != null) {
            signer.setParameter(pss);
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
            parameters.init(pss);
            identifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                    ASN1Primitive.fromByteArray(parameters.getEncoded()));
        } else {
            identifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        }
        signer.initSign(keys.getPrivate());
        signer.update(info.getEncoded());
        return CsrRequest.fromDer(new DERSequence(new ASN1Encodable[]{
                info, identifier, new DERBitString(signer.sign())}).getEncoded());
    }

    private record CountedIssuer(PkiIdentity identity, AtomicInteger calls) {}
}
