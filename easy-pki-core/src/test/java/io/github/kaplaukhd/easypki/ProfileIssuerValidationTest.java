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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyConstraints;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class ProfileIssuerValidationTest {
    private static final KeyPair ROOT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ISSUER_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair ROLLOVER_KEYS = PkiKeys.ec(Curve.P_256);
    private static final Instant START = Instant.parse("2020-01-01T00:00:00Z");
    private static final Instant END = Instant.parse("2040-01-01T00:00:00Z");
    private static final Instant CHILD_START = Instant.parse("2030-01-01T00:00:00Z");
    private static final Instant CHILD_END = Instant.parse("2031-01-01T00:00:00Z");
    private static final int SIGNING = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
    private static final AtomicInteger SERIAL = new AtomicInteger();
    private static final X500Principal CHILD = new X500Principal("CN=Child");

    @Test
    void zeroPathLengthAllowsTlsButRejectsOrdinaryIntermediate() throws Exception {
        var issuer = checked(ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0), ROOT_KEYS);
        assertThatCode(() -> tls(issuer)).doesNotThrowAnyException();
        assertThatThrownBy(() -> intermediate(issuer, CHILD, 0))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("path length");
    }

    @Test
    void sameDnRolloverDoesNotConsumeAPathLevel() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0);
        var issuer = checked(root, ROOT_KEYS);
        assertThatCode(() -> intermediate(issuer, root.getSubjectX500Principal(), 0))
                .doesNotThrowAnyException();
        var rollover = ca("CN=Root", ROLLOVER_KEYS, root, ROOT_KEYS, 0);
        assertThatCode(() -> tls(checked(rollover, ROLLOVER_KEYS, root))).doesNotThrowAnyException();
    }

    @Test
    void selfIssuedAncestorDoesNotConsumeAnotherPathLevel() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1);
        var rollover = ca("CN=Root", ROLLOVER_KEYS, root, ROOT_KEYS, 1);
        var issuer = ca("CN=Issuer", ISSUER_KEYS, rollover, ROLLOVER_KEYS, 0);
        assertThatCode(() -> tls(checked(issuer, ISSUER_KEYS, rollover, root))).doesNotThrowAnyException();
    }

    @Test
    void suppliedGrandparentPathLimitAppliesToTlsIssuance() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0);
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, null);
        assertThatThrownBy(() -> tls(checked(issuer, ISSUER_KEYS, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("path length");
    }

    @Test
    void intermediateBudgetMustFitEveryAncestorRemainingAllowance() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 2);
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, null);
        var identity = checked(issuer, ISSUER_KEYS, root);
        assertThatCode(() -> intermediate(identity, CHILD, 0)).doesNotThrowAnyException();
        assertThatThrownBy(() -> intermediate(identity, CHILD, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("remaining issuer allowance");
    }

    @Test
    void unlimitedAndMaximumIntegerLimitsRemainDistinctWithoutOverflow() throws Exception {
        var unlimited = checked(ca("CN=Unlimited", ROOT_KEYS, null, ROOT_KEYS, null), ROOT_KEYS);
        var finite = checked(ca("CN=Finite", ROOT_KEYS, null, ROOT_KEYS, Integer.MAX_VALUE), ROOT_KEYS);
        assertThatCode(() -> intermediate(unlimited, CHILD, Integer.MAX_VALUE)).doesNotThrowAnyException();
        assertThatThrownBy(() -> intermediate(finite, CHILD, Integer.MAX_VALUE))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("path length");
        assertThatCode(() -> intermediate(finite, CHILD, Integer.MAX_VALUE - 1)).doesNotThrowAnyException();
    }

    @Test
    void absentRootIsNotInventedOrRequired() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0);
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, 0);
        assertThatCode(() -> tls(checked(issuer, ISSUER_KEYS))).doesNotThrowAnyException();
    }

    @Test
    void requestedIntervalMayEqualIssuerEndpoints() throws Exception {
        var issuer = checked(ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0), ROOT_KEYS);
        assertThatCode(() -> validate(issuer, false, null, START, END, ExtendedKeyUsage.TLS_SERVER))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void requestedIntervalCannotExceedIssuer(boolean exceedEnd) throws Exception {
        var issuer = checked(ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0), ROOT_KEYS);
        assertThatThrownBy(() -> validate(issuer, false, null,
                exceedEnd ? START : START.minusSeconds(1),
                exceedEnd ? END.plusSeconds(1) : END, ExtendedKeyUsage.TLS_SERVER))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("validity");
    }

    @Test
    void suppliedAncestorValidityBoundsTheNewCertificate() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1);
        var issuer = certificate("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS,
                new BasicConstraints(0), true, SIGNING, START.minusSeconds(1), END.plusSeconds(1));
        assertThatThrownBy(() -> validate(checked(issuer, ISSUER_KEYS, root), false, null,
                START, END.plusSeconds(1), ExtendedKeyUsage.TLS_SERVER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("validity");
    }

    @ParameterizedTest
    @ValueSource(strings = {"2000-01-01T00:00:00Z", "2070-01-01T00:00:00Z"})
    void historicalAndFutureContainedIntervalsDoNotDependOnWallClock(String start) throws Exception {
        Instant from = Instant.parse(start);
        var certificate = certificate("CN=Scheduled", ROOT_KEYS, null, ROOT_KEYS,
                new BasicConstraints(0), true, SIGNING, from, from.plusSeconds(100));
        assertThatCode(() -> validate(checked(certificate, ROOT_KEYS), false, null,
                from.plusSeconds(1), from.plusSeconds(99), ExtendedKeyUsage.TLS_CLIENT))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"absent", "noncritical", "not-ca"})
    void issuerMustHaveCriticalCaBasicConstraints(String mode) throws Exception {
        BasicConstraints constraints = mode.equals("absent") ? null : new BasicConstraints(!mode.equals("not-ca"));
        var certificate = certificate("CN=Invalid", ROOT_KEYS, null, ROOT_KEYS,
                constraints, !mode.equals("noncritical"), SIGNING, START, END);
        assertThatThrownBy(() -> tls(checked(certificate, ROOT_KEYS)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("BasicConstraints");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void issuerMustExplicitlyPermitCertificateSigning(boolean absent) throws Exception {
        var certificate = certificate("CN=Invalid", ROOT_KEYS, null, ROOT_KEYS,
                new BasicConstraints(true), true,
                absent ? null : org.bouncycastle.asn1.x509.KeyUsage.digitalSignature, START, END);
        assertThatThrownBy(() -> tls(checked(certificate, ROOT_KEYS)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("keyCertSign");
    }

    @Test
    void explicitlyPermittedNoncriticalKeyUsageIsAccepted() throws Exception {
        var certificate = certificate("CN=Root", ROOT_KEYS, null, ROOT_KEYS,
                new BasicConstraints(0), true, null, START, END,
                extension(Extension.keyUsage, false, new org.bouncycastle.asn1.x509.KeyUsage(SIGNING)));
        assertThatCode(() -> tls(checked(certificate, ROOT_KEYS))).doesNotThrowAnyException();
    }

    @Test
    void issuerCaSubjectMustBeNonemptyEvenWithCriticalSan() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1);
        var issuer = ca("", ISSUER_KEYS, root, ROOT_KEYS, 0,
                extension(Extension.subjectAlternativeName, true,
                        new org.bouncycastle.asn1.x509.GeneralNames(
                                new GeneralName(GeneralName.dNSName, "ca.example.com"))));
        assertThatThrownBy(() -> tls(checked(issuer, ISSUER_KEYS, root)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("CA subject must not be empty");
    }

    @Test
    void invalidSuppliedAncestorCannotHideBehindAnAuthorizedDirectIssuer() throws Exception {
        var root = certificate("CN=Root", ROOT_KEYS, null, ROOT_KEYS,
                new BasicConstraints(false), true, SIGNING, START, END);
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, 0);
        assertThatThrownBy(() -> tls(checked(issuer, ISSUER_KEYS, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("CA:true");
    }

    @ParameterizedTest
    @MethodSource("unsupportedConstraints")
    void unsupportedConstraintIsRejectedRegardlessOfCriticality(ASN1ObjectIdentifier oid,
                                                               ASN1Encodable value, boolean critical)
            throws Exception {
        var certificate = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0, extension(oid, critical, value));
        assertThatThrownBy(() -> tls(checked(certificate, ROOT_KEYS)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsupported issuer constraint").hasMessageContaining(oid.getId());
    }

    @Test
    void constraintsOnSuppliedAncestorsAreAlsoRejected() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1,
                extension(Extension.nameConstraints, false, new NameConstraints(new GeneralSubtree[]{
                        new GeneralSubtree(new GeneralName(GeneralName.dNSName, "example.com"))}, null)));
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, 0);
        assertThatThrownBy(() -> tls(checked(issuer, ISSUER_KEYS, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("nameConstraints");
    }

    @Test
    void unknownCriticalExtensionRejectsButNoncriticalExtensionDoesNot() throws Exception {
        var oid = new ASN1ObjectIdentifier("1.2.3.4.5.6");
        var critical = ca("CN=Critical", ROOT_KEYS, null, ROOT_KEYS, 0, extension(oid, true, DERNull.INSTANCE));
        var optional = ca("CN=Optional", ROOT_KEYS, null, ROOT_KEYS, 0, extension(oid, false, DERNull.INSTANCE));
        assertThatThrownBy(() -> tls(checked(critical, ROOT_KEYS)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("critical extension");
        assertThatCode(() -> tls(checked(optional, ROOT_KEYS))).doesNotThrowAnyException();
    }

    @Test
    void jcaRecognizedCriticalExtensionStillNeedsPreflightSupport() throws Exception {
        var issuer = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 0,
                extension(Extension.subjectAlternativeName, true,
                        new org.bouncycastle.asn1.x509.GeneralNames(
                                new GeneralName(GeneralName.dNSName, "ca.example.com"))));
        assertThat(issuer.hasUnsupportedCriticalExtension()).isFalse();
        assertThatThrownBy(() -> tls(checked(issuer, ROOT_KEYS)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("unsupported critical extension");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void tlsIssuerEkuMustAllowTheRequestedPurpose(boolean critical) throws Exception {
        var certificate = ca("CN=Server CA", ROOT_KEYS, null, ROOT_KEYS, 0,
                eku(critical, KeyPurposeId.id_kp_serverAuth));
        var issuer = checked(certificate, ROOT_KEYS);
        assertThatCode(() -> tls(issuer)).doesNotThrowAnyException();
        assertThatThrownBy(() -> validate(issuer, false, null, CHILD_START, CHILD_END, ExtendedKeyUsage.TLS_CLIENT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("ExtendedKeyUsage");
    }

    @Test
    void anyExtendedKeyUsageAllowsEitherTlsPurpose() throws Exception {
        var certificate = ca("CN=Any Purpose", ROOT_KEYS, null, ROOT_KEYS, 0,
                eku(false, KeyPurposeId.anyExtendedKeyUsage));
        var issuer = checked(certificate, ROOT_KEYS);
        assertThatCode(() -> tls(issuer)).doesNotThrowAnyException();
        assertThatCode(() -> validate(issuer, false, null, CHILD_START, CHILD_END, ExtendedKeyUsage.TLS_CLIENT))
                .doesNotThrowAnyException();
    }

    @Test
    void ancestorEkuAlsoRestrictsTlsIssuance() throws Exception {
        var root = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1, eku(false, KeyPurposeId.id_kp_clientAuth));
        var issuer = ca("CN=Issuer", ISSUER_KEYS, root, ROOT_KEYS, 0);
        assertThatThrownBy(() -> tls(checked(issuer, ISSUER_KEYS, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("chain index 1").hasMessageContaining("ExtendedKeyUsage");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void caIssuanceUnderAnyEkuRestrictionIsExplicitlyUnsupported(boolean any) throws Exception {
        var certificate = ca("CN=Root", ROOT_KEYS, null, ROOT_KEYS, 1,
                eku(false, any ? KeyPurposeId.anyExtendedKeyUsage : KeyPurposeId.id_kp_serverAuth));
        assertThatThrownBy(() -> intermediate(checked(certificate, ROOT_KEYS), CHILD, 0))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("CA issuance")
                .hasMessageContaining("ExtendedKeyUsage");
    }

    private static Stream<Arguments> unsupportedConstraints() {
        ASN1ObjectIdentifier[] oids = {Extension.nameConstraints, Extension.policyConstraints,
                Extension.policyMappings, Extension.inhibitAnyPolicy};
        ASN1Encodable[] values = {
                new NameConstraints(new GeneralSubtree[]{
                        new GeneralSubtree(new GeneralName(GeneralName.dNSName, "example.com"))}, null),
                new PolicyConstraints(BigInteger.ZERO, null),
                new DERSequence(new DERSequence(new ASN1Encodable[]{
                        new ASN1ObjectIdentifier("1.2.3.4"), new ASN1ObjectIdentifier("1.2.3.5")})),
                new ASN1Integer(0)};
        return java.util.stream.IntStream.range(0, oids.length).boxed()
                .flatMap(i -> Stream.of(Arguments.of(oids[i], values[i], false),
                        Arguments.of(oids[i], values[i], true)));
    }

    private static Extension eku(boolean critical, KeyPurposeId purpose) throws Exception {
        return extension(Extension.extendedKeyUsage, critical,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(purpose));
    }

    private static Extension extension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value)
            throws Exception {
        return new Extension(oid, critical, value.toASN1Primitive().getEncoded());
    }

    private static X509Certificate ca(String subject, KeyPair keys, X509Certificate issuer,
                                      KeyPair issuerKeys, Integer limit, Extension... extras) throws Exception {
        return certificate(subject, keys, issuer, issuerKeys,
                limit == null ? new BasicConstraints(true) : new BasicConstraints(limit),
                true, SIGNING, START, END, extras);
    }

    private static X509Certificate certificate(String subject, KeyPair keys, X509Certificate issuer,
                                               KeyPair issuerKeys, BasicConstraints constraints,
                                               boolean critical, Integer usage,
                                               Instant from, Instant until, Extension... extras) throws Exception {
        var name = new X500Principal(subject);
        var builder = new JcaX509v3CertificateBuilder(
                issuer == null ? name : issuer.getSubjectX500Principal(),
                BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(from), Date.from(until), name,
                keys.getPublic());
        if (constraints != null) builder.addExtension(Extension.basicConstraints, critical, constraints);
        if (usage != null) builder.addExtension(Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(usage));
        for (Extension extra : extras) builder.addExtension(extra);
        return CertificateBuildSupport.toX509Certificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }

    private static CheckedIssuer checked(X509Certificate leaf, KeyPair keys, X509Certificate... chain) {
        var calls = new AtomicInteger();
        var delegate = PkiSigner.jca(keys.getPrivate());
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return delegate.signatureAlgorithm(); }
            @Override public byte[] sign(byte[] data) throws GeneralSecurityException {
                calls.incrementAndGet();
                return delegate.sign(data);
            }
        };
        var identity = PkiIdentity.of(leaf, signer, chain);
        assertThat(calls.get()).as("identity possession proof").isEqualTo(1);
        calls.set(0);
        return new CheckedIssuer(identity, calls);
    }

    private static void tls(CheckedIssuer issuer) {
        validate(issuer, false, null, CHILD_START, CHILD_END, ExtendedKeyUsage.TLS_SERVER);
    }

    private static void intermediate(CheckedIssuer issuer, X500Principal subject, int limit) {
        try {
            ProfileIssuerValidation.validate(issuer.identity(), subject, true, limit, CHILD_START, CHILD_END, null);
        } finally {
            assertThat(issuer.calls().get()).as("preflight must not sign").isZero();
        }
    }

    private static void validate(CheckedIssuer issuer, boolean ca, Integer limit,
                                 Instant from, Instant until, ExtendedKeyUsage purpose) {
        try {
            ProfileIssuerValidation.validate(issuer.identity(), CHILD, ca, limit, from, until, purpose);
        } finally {
            assertThat(issuer.calls().get()).as("preflight must not sign").isZero();
        }
    }

    private record CheckedIssuer(PkiIdentity identity, AtomicInteger calls) {}
}
