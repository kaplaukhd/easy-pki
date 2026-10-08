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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class CertificateProfilesTest {
    private static final String BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String KEY_USAGE = "2.5.29.15";
    private static final String EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final String SAN = "2.5.29.17";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final Instant CA_START = Instant.parse("2025-01-01T00:00:00Z");
    private static final Instant CA_END = Instant.parse("2035-01-01T00:00:00Z");
    private static final Instant LEAF_START = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant LEAF_END = Instant.parse("2027-01-01T00:00:00Z");
    private static final KeyPair RSA = PkiKeys.rsa(2048);
    private static final KeyPair EC = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ED = PkiKeys.ed25519();
    private static X509Certificate root;
    private static PkiIdentity issuer;

    @BeforeAll
    static void createIssuer() {
        root = rootBuilder(ED).build();
        issuer = PkiIdentity.of(root, ED.getPrivate());
    }

    static Stream<Arguments> subjectKeys() {
        return Stream.of(Arguments.of("RSA", RSA), Arguments.of("EC", EC), Arguments.of("Ed25519", ED));
    }

    @ParameterizedTest(name = "CA defaults with {0}")
    @MethodSource("subjectKeys")
    void caProfilesEncodeRoleDefaultsForEveryKeyFamily(String keyType, KeyPair keys) throws Exception {
        X509Certificate ca = decode(rootBuilder(keys).subject("CN=" + keyType + " Root").build());
        assertCa(ca, Integer.MAX_VALUE);
        ca.verify(ca.getPublicKey());
        X509Certificate intermediate = decode(PkiCertificate.intermediateCa().subject("CN=" + keyType + " Intermediate")
                .keyPair(keys).issuer(issuer).validFrom(LEAF_START).validUntil(LEAF_END).build());
        assertCa(intermediate, 0);
        intermediate.verify(root.getPublicKey());
    }

    @ParameterizedTest(name = "TLS defaults with {0}")
    @MethodSource("subjectKeys")
    void tlsProfilesUseSigningOnlyAndExactlyTheirOwnEku(String keyType, KeyPair keys) throws Exception {
        X509Certificate server = decode(issued(PkiCertificate.tlsServer(), keys)
                .subject("CN=" + keyType + " Server").san(s -> s.dns("service.example.com")).build());
        X509Certificate client = decode(issued(PkiCertificate.tlsClient(), keys)
                .subject("CN=" + keyType + " Client").build());
        assertTls(server, SERVER_AUTH, 0);
        assertTls(client, CLIENT_AUTH, 0);
        assertThat(server.getNonCriticalExtensionOIDs()).contains(SAN);
        assertThat(client.getSubjectAlternativeNames()).isNull();
        server.verify(root.getPublicKey());
        client.verify(root.getPublicKey());
    }

    @Test
    void emptyTlsSubjectsAreEncodedWithCriticalIdentitySans() throws Exception {
        X509Certificate server = decode(issued(PkiCertificate.tlsServer(), ED)
                .san(s -> s.dns("service.example.com").ip("192.0.2.10")).build());
        X509Certificate client = decode(issued(PkiCertificate.tlsClient(), ED).subject("")
                .san(s -> s.uri("spiffe://example.org/workload").email("alice@example.com")).build());
        for (X509Certificate certificate : List.of(server, client)) {
            assertThat(certificate.getSubjectX500Principal().getName()).isEmpty();
            assertThat(certificate.getCriticalExtensionOIDs()).contains(SAN);
            assertThat(certificate.getNonCriticalExtensionOIDs()).doesNotContain(SAN);
            assertThat(certificate.getSubjectAlternativeNames()).hasSize(2);
        }
    }

    @Test
    void clientIdentityDoesNotRequireOrInventServerNames() throws Exception {
        X509Certificate subjectOnly = decode(issued(PkiCertificate.tlsClient(), ED)
                .subject("UID=workload-123,O=Example").build());
        assertThat(subjectOnly.getSubjectAlternativeNames()).isNull();
        assertTls(subjectOnly, CLIENT_AUTH, 0);
        X509Certificate uriOnly = decode(issued(PkiCertificate.tlsClient(), ED)
                .san(s -> s.uri("urn:example:workload:123")).build());
        assertThat(uriOnly.getSubjectAlternativeNames()).singleElement().satisfies(name -> {
            assertThat(name.get(0)).isEqualTo(6);
            assertThat(name.get(1)).isEqualTo("urn:example:workload:123");
        });
        assertTls(uriOnly, CLIENT_AUTH, 0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"X25519", "X448"})
    void agreementOnlySubjectKeysAreRejectedBeforeSigning(String algorithm) throws Exception {
        var keys = java.security.KeyPairGenerator.getInstance(algorithm).generateKeyPair();
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        PkiIdentity identity = PkiIdentity.of(root, signer);
        for (CertificateProfile profile : java.util.List.of(CertificateProfile.INTERMEDIATE_CA,
                CertificateProfile.TLS_SERVER, CertificateProfile.TLS_CLIENT)) {
            signer.calls.set(0);
            rejectedBeforeSigning(signer, () -> PkiCertificate.signed().profile(profile)
                    .subject("CN=Agreement Subject").publicKey(keys.getPublic()).issuer(identity)
                    .validFrom(LEAF_START).validUntil(LEAF_END)
                    .san(s -> s.dns("service.example.com")).build());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void selfSignedTlsRequiresNonemptyIssuerDnBeforeSigning(boolean server) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        rejectedBeforeSigning(signer, () -> PkiCertificate.selfSigned()
                .profile(server ? CertificateProfile.TLS_SERVER : CertificateProfile.TLS_CLIENT)
                .signer(ED.getPublic(), signer).validFrom(LEAF_START).validUntil(LEAF_END)
                .san(s -> s.dns("service.example.com")).build());
    }

    @Test
    void selfSignedTlsProfilesHaveTheSameRoleAndIdentityRules() throws Exception {
        X509Certificate server = decode(PkiCertificate.selfSigned().profile(CertificateProfile.TLS_SERVER)
                .subject("CN=service.example.com").keyPair(ED).validFrom(LEAF_START).validUntil(LEAF_END)
                .san(s -> s.dns("service.example.com")).build());
        X509Certificate client = decode(PkiCertificate.selfSigned().profile(CertificateProfile.TLS_CLIENT)
                .subject("CN=Client").keyPair(EC).validFrom(LEAF_START).validUntil(LEAF_END).build());
        assertTls(server, SERVER_AUTH, 0);
        assertTls(client, CLIENT_AUTH, 0);
        assertThat(server.getCriticalExtensionOIDs()).doesNotContain(SAN);
        server.verify(server.getPublicKey());
        client.verify(client.getPublicKey());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void compatibleExplicitSettingsAccumulateRegardlessOfProfileOrder(boolean profileFirst) throws Exception {
        SignedCertificateBuilder builder = issued(PkiCertificate.signed(), RSA).subject("CN=Server");
        if (profileFirst) builder.profile(CertificateProfile.TLS_SERVER);
        builder.isCA(false).keyUsage(KeyUsage.KEY_ENCIPHERMENT).keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER).extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
                .san(s -> s.dns("service.example.com"));
        if (!profileFirst) builder.profile(CertificateProfile.TLS_SERVER);
        assertTls(decode(builder.build()), SERVER_AUTH, 0, 2);

        SelfSignedCertificateBuilder ca = PkiCertificate.selfSigned().subject("CN=Bounded Root")
                .keyPair(ED).validFrom(CA_START).validUntil(CA_END);
        if (profileFirst) ca.profile(CertificateProfile.ROOT_CA);
        ca.pathLength(2).keyUsage(KeyUsage.KEY_CERT_SIGN).keyUsage(KeyUsage.CRL_SIGN);
        if (!profileFirst) ca.profile(CertificateProfile.ROOT_CA);
        assertCa(decode(ca.build()), 2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ca", "path", "cert-sign", "crl-sign", "data-encipherment", "key-agreement",
            "client-eku", "extra-eku", "no-san", "empty-san", "email-san", "uri-san", "invalid-dns", "cidr"})
    void serverConflictsFailBeforeCallingTheIssuerSigner(String conflict) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        PkiIdentity countedIssuer = PkiIdentity.of(root, signer);
        signer.calls.set(0);
        rejectedBeforeSigning(signer, () -> {
            SignedCertificateBuilder builder = issued(PkiCertificate.tlsServer(), ED).issuer(countedIssuer)
                    .subject("CN=service.example.com");
            if (!conflict.equals("no-san") && !conflict.equals("empty-san")) {
                builder.san(s -> s.dns("service.example.com"));
            }
            switch (conflict) {
                case "ca" -> builder.isCA(true);
                case "path" -> builder.pathLength(0);
                case "cert-sign" -> builder.keyUsage(KeyUsage.KEY_CERT_SIGN);
                case "crl-sign" -> builder.keyUsage(KeyUsage.CRL_SIGN);
                case "data-encipherment" -> builder.keyUsage(KeyUsage.DATA_ENCIPHERMENT);
                case "key-agreement" -> builder.keyUsage(KeyUsage.KEY_AGREEMENT);
                case "client-eku" -> builder.extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT);
                case "extra-eku" -> builder.extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.CODE_SIGNING);
                case "empty-san" -> builder.san(s -> {});
                case "email-san" -> builder.san(s -> s.email("alice@example.com"));
                case "uri-san" -> builder.san(s -> s.uri("urn:example:server"));
                case "invalid-dns" -> builder.san(s -> s.dns("bad_name.example.com"));
                case "cidr" -> builder.san(s -> s.ip("192.0.2.10/24"));
                default -> { }
            }
            return builder.build();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-identity", "empty-subject", "server-eku", "encipherment", "bad-email", "relative-uri"})
    void clientConflictsFailBeforeCallingTheIssuerSigner(String conflict) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        PkiIdentity countedIssuer = PkiIdentity.of(root, signer);
        signer.calls.set(0);
        rejectedBeforeSigning(signer, () -> {
            SignedCertificateBuilder builder = issued(PkiCertificate.tlsClient(), RSA).issuer(countedIssuer);
            if (!conflict.equals("no-identity") && !conflict.equals("empty-subject")) builder.subject("CN=Client");
            switch (conflict) {
                case "empty-subject" -> builder.subject("");
                case "server-eku" -> builder.extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER);
                case "encipherment" -> builder.keyUsage(KeyUsage.KEY_ENCIPHERMENT);
                case "bad-email" -> builder.san(s -> s.email("not-a-mailbox"));
                case "relative-uri" -> builder.san(s -> s.uri("relative/path"));
                default -> { }
            }
            return builder.build();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-ca", "digital-signature", "eku", "empty-subject", "missing-subject", "intermediate-role"})
    void rootConflictsFailBeforeCallingTheRootSigner(String conflict) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        rejectedBeforeSigning(signer, () -> {
            SelfSignedCertificateBuilder builder = PkiCertificate.rootCa().signer(ED.getPublic(), signer)
                    .validFrom(CA_START).validUntil(CA_END);
            if (!conflict.equals("missing-subject")) builder.subject("CN=Root");
            switch (conflict) {
                case "not-ca" -> builder.isCA(false);
                case "digital-signature" -> builder.keyUsage(KeyUsage.DIGITAL_SIGNATURE);
                case "eku" -> builder.extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER);
                case "empty-subject" -> builder.subject("");
                case "intermediate-role" -> builder.profile(CertificateProfile.INTERMEDIATE_CA);
                default -> { }
            }
            return builder.build();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"EC", "Ed25519"})
    void nonRsaServerKeysCannotRequestKeyEncipherment(String keyType) {
        assertThatThrownBy(() -> issued(PkiCertificate.tlsServer(), keyType.equals("EC") ? EC : ED)
                .san(s -> s.dns("service.example.com")).keyUsage(KeyUsage.KEY_ENCIPHERMENT).build())
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
    }

    @Test
    void profiledIssuanceRequiresACheckedIdentityAndCannotRetainOneAfterIssuerReplacement() {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        rejectedBeforeSigning(signer, () -> issued(PkiCertificate.tlsServer(), ED)
                .san(s -> s.dns("service.example.com")).issuer(root, signer).build());
        assertThatThrownBy(() -> issued(PkiCertificate.tlsServer(), ED)
                .san(s -> s.dns("service.example.com")).issuer(root, ED.getPrivate()).build())
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThatThrownBy(() -> issued(PkiCertificate.signed().profile(CertificateProfile.ROOT_CA), ED)
                .subject("CN=Root").build())
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dns", "email", "uri"})
    void unicodeTruncationIsRejectedEvenThroughARetainedSanBuilderAndLateProfile(String type) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        PkiIdentity countedIssuer = PkiIdentity.of(root, signer);
        signer.calls.set(0);
        rejectedBeforeSigning(signer, () -> {
            AtomicReference<SanBuilder> retained = new AtomicReference<>();
            SignedCertificateBuilder builder = issued(PkiCertificate.signed(), ED).issuer(countedIssuer)
                    .subject("CN=Client").san(retained::set);
            switch (type) {
                case "dns" -> retained.get().dns("\u0161.example.com");
                case "email" -> retained.get().email("\u0161@example.com");
                case "uri" -> retained.get().uri("urn:example:\u0161");
                default -> throw new AssertionError(type);
            }
            return builder.profile(CertificateProfile.TLS_CLIENT).build();
        });
    }

    @Test
    void explicitPssRootAndIssuerSignersKeepTheirParametersAndProviderIsolation() throws Exception {
        Provider[] before = Security.getProviders();
        PkiSigner pss = PkiSigner.rsaPss(RSA.getPrivate(), RsaPssParameters.sha256(), "SunRsaSign");
        X509Certificate pssRoot = decode(PkiCertificate.rootCa().subject("CN=PSS Root")
                .signer(RSA.getPublic(), pss).validFrom(CA_START).validUntil(CA_END).build());
        PkiIdentity pssIssuer = PkiIdentity.of(pssRoot, pss);
        X509Certificate leaf = decode(issued(PkiCertificate.tlsServer(), EC).issuer(pssIssuer)
                .san(s -> s.dns("service.example.com")).build());
        assertThat(pssRoot.getSigAlgOID()).isEqualTo("1.2.840.113549.1.1.10");
        assertThat(leaf.getSigAlgOID()).isEqualTo(pssRoot.getSigAlgOID());
        assertThat(leaf.getSigAlgParams()).isEqualTo(pssRoot.getSigAlgParams());
        pssRoot.verify(RSA.getPublic(), "SunRsaSign");
        leaf.verify(RSA.getPublic(), "SunRsaSign");
        assertThat(Security.getProviders()).containsExactly(before);
    }

    @Test
    void profileDatesUseEncodedSecondsAndRejectCollapsedIntervalsBeforeSigning() throws Exception {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        Instant fractional = LEAF_START.plusNanos(123_000_000);
        rejectedBeforeSigning(signer, () -> PkiCertificate.rootCa().subject("CN=Tiny")
                .signer(ED.getPublic(), signer).validFrom(fractional).validFor(Duration.ofNanos(1)).build());
        X509Certificate rootWithFraction = PkiCertificate.rootCa().subject("CN=Seconds")
                .keyPair(ED).validFrom(fractional).validUntil(LEAF_END.plusNanos(999_999_999)).build();
        assertThat(rootWithFraction.getNotBefore().toInstant()).isEqualTo(LEAF_START);
        assertThat(rootWithFraction.getNotAfter().toInstant()).isEqualTo(LEAF_END);
        PkiIdentity identity = PkiIdentity.of(rootWithFraction, ED.getPrivate());
        X509Certificate leaf = PkiCertificate.tlsServer().keyPair(EC).issuer(identity)
                .validFrom(fractional).validUntil(LEAF_END.plusNanos(999_999_999))
                .san(n -> n.dns("service.example.com")).build();
        assertThat(leaf.getNotAfter()).isEqualTo(rootWithFraction.getNotAfter());
    }

    @ParameterizedTest
    @ValueSource(strings = {"1949-12-31T23:59:59Z", "+10000-01-01T00:00:00Z"})
    void unencodableProfileDatesFailBeforeSigning(String timestamp) {
        CountingSigner signer = new CountingSigner(PkiSigner.jca(ED.getPrivate()));
        Instant time = Instant.parse(timestamp);
        rejectedBeforeSigning(signer, () -> PkiCertificate.rootCa().subject("CN=Bad Date")
                .signer(ED.getPublic(), signer).validFrom(time).validFor(Duration.ofDays(1)).build());
    }

    @Test
    void profileDoesNotReturnCertificateSignedWithTheWrongKey() {
        assertThatThrownBy(() -> PkiCertificate.rootCa().subject("CN=Wrong Signing Key")
                .signer(ED.getPublic(), PkiSigner.jca(EC.getPrivate()))
                .validFrom(LEAF_START).validUntil(LEAF_END).build())
                .isInstanceOf(IllegalStateException.class).hasCauseInstanceOf(java.security.GeneralSecurityException.class);
    }

    @Test
    void repeatedBuildsKeepSanSnapshotsAndFreshRawBuildersKeepLegacyBehavior() throws Exception {
        SignedCertificateBuilder builder = issued(PkiCertificate.tlsServer(), ED)
                .subject("CN=Server").san(s -> s.dns("first.example.com"));
        X509Certificate first = decode(builder.build());
        X509Certificate second = decode(builder.san(s -> s.dns("second.example.com")).build());
        assertThat(first.getSubjectAlternativeNames()).hasSize(1);
        assertThat(second.getSubjectAlternativeNames()).hasSize(2);
        assertTls(first, SERVER_AUTH, 0);
        assertTls(second, SERVER_AUTH, 0);
        X509Certificate raw = decode(PkiCertificate.signed().subject("CN=Raw").keyPair(ED)
                .issuer(root, ED.getPrivate()).validFrom(LEAF_START).validUntil(LEAF_END).build());
        assertThat(raw.getKeyUsage()).isNull();
        assertThat(raw.getExtendedKeyUsage()).isNull();
        assertThat(raw.getSubjectAlternativeNames()).isNull();
        X509Certificate rawNames = decode(PkiCertificate.selfSigned().subject("CN=Raw Names").keyPair(ED)
                .validFrom(LEAF_START).validUntil(LEAF_END).san(s -> s.dns("bad_name.example").uri("relative/path"))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT).build());
        // The raw builder still encodes caller text without profile checks;
        // SUN can mark such a SAN unparseable, so inspect its preserved DER.
        byte[] sanValue = org.bouncycastle.asn1.ASN1OctetString.getInstance(rawNames.getExtensionValue(SAN)).getOctets();
        assertThat(org.bouncycastle.asn1.x509.GeneralNames.getInstance(sanValue).getNames()).hasSize(2);
        assertThat(rawNames.getExtendedKeyUsage()).containsExactly(SERVER_AUTH, CLIENT_AUTH);
    }

    private static SelfSignedCertificateBuilder rootBuilder(KeyPair keys) {
        return PkiCertificate.rootCa().subject("CN=Profile Root").keyPair(keys)
                .validFrom(CA_START).validUntil(CA_END);
    }

    private static SignedCertificateBuilder issued(SignedCertificateBuilder builder, KeyPair keys) {
        return builder.keyPair(keys).issuer(issuer).validFrom(LEAF_START).validUntil(LEAF_END);
    }

    private static X509Certificate decode(X509Certificate certificate) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", "SUN")
                .generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    private static void assertCa(X509Certificate certificate, int pathLength) throws Exception {
        assertThat(certificate.getBasicConstraints()).isEqualTo(pathLength);
        assertUsages(certificate, 5, 6);
        assertThat(certificate.getCriticalExtensionOIDs()).containsExactlyInAnyOrder(BASIC_CONSTRAINTS, KEY_USAGE);
        assertThat(certificate.getExtendedKeyUsage()).isNull();
        assertThat(certificate.getExtensionValue("2.5.29.14")).isNotNull();
        assertThat(certificate.getExtensionValue("2.5.29.35")).isNotNull();
    }

    private static void assertTls(X509Certificate certificate, String eku, Integer... keyBits) throws Exception {
        assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
        assertUsages(certificate, keyBits);
        assertThat(certificate.getCriticalExtensionOIDs()).contains(BASIC_CONSTRAINTS, KEY_USAGE)
                .doesNotContain(EXTENDED_KEY_USAGE);
        assertThat(certificate.getNonCriticalExtensionOIDs()).contains(EXTENDED_KEY_USAGE);
        assertThat(certificate.getExtendedKeyUsage()).containsExactly(eku);
    }

    private static void assertUsages(X509Certificate certificate, Integer... bits) {
        boolean[] usage = certificate.getKeyUsage();
        assertThat(usage).isNotNull();
        assertThat(IntStream.range(0, usage.length).filter(index -> usage[index]).boxed().toList())
                .containsExactly(bits);
    }

    private static void rejectedBeforeSigning(CountingSigner signer, Supplier<X509Certificate> action) {
        assertThatThrownBy(action::get).isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(signer.calls).hasValue(0);
    }

    private static final class CountingSigner implements PkiSigner {
        private final PkiSigner delegate;
        private final AtomicInteger calls = new AtomicInteger();

        private CountingSigner(PkiSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public String signatureAlgorithm() {
            return delegate.signatureAlgorithm();
        }

        @Override
        public AlgorithmParameterSpec signatureParameters() {
            return delegate.signatureParameters();
        }

        @Override
        public byte[] sign(byte[] content) throws GeneralSecurityException {
            calls.incrementAndGet();
            return delegate.sign(content);
        }
    }
}
