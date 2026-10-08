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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.io.Serial;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class PkiCertificateSerialTest {

    private static KeyPair issuerKeys;
    private static KeyPair subjectKeys;
    private static X509Certificate issuer;

    @BeforeAll
    static void setUpIssuer() {
        issuerKeys = PkiKeys.ec(Curve.P_256);
        subjectKeys = PkiKeys.ec(Curve.P_256);
        issuer = PkiCertificate.selfSigned()
                .subject("CN=Serial Test CA")
                .keyPair(issuerKeys)
                .validFor(Duration.ofDays(1))
                .serialNumber(BigInteger.ONE)
                .isCA(true)
                .build();
    }

    @ParameterizedTest
    @EnumSource(BuilderType.class)
    void generatedSerialsArePositiveAndFitTwentyDerValueOctets(BuilderType type) throws Exception {
        SelfSignedCertificateBuilder selfSigned = selfSigned();
        SignedCertificateBuilder signed = signed();
        BigInteger previous = null;
        for (int i = 0; i < 32; i++) {
            X509Certificate certificate = type == BuilderType.SELF_SIGNED
                    ? selfSigned.build() : signed.build();
            BigInteger serial = certificate.getSerialNumber();

            assertThat(serial.signum()).isOne();
            assertThat(serial.bitLength()).isLessThanOrEqualTo(159);
            assertThat(serial).isNotEqualTo(previous);
            assertThat(serialDerValueLength(certificate)).isBetween(1, 20);
            previous = serial;
        }
    }

    @ParameterizedTest
    @MethodSource("validSerials")
    void explicitBoundarySerialsArePreservedInDer(
            BuilderType type, BigInteger serial, int expectedValueOctets) throws Exception {
        X509Certificate certificate = type == BuilderType.SELF_SIGNED
                ? selfSigned().serialNumber(serial).build()
                : signed().serialNumber(serial).build();

        assertThat(certificate.getSerialNumber()).isEqualTo(serial);
        assertThat(serialDerValueLength(certificate)).isEqualTo(expectedValueOctets);
        certificate.verify(type == BuilderType.SELF_SIGNED
                ? subjectKeys.getPublic() : issuerKeys.getPublic());
    }

    @ParameterizedTest
    @MethodSource("invalidSerials")
    void invalidExplicitSerialsAreRejectedBeforeBuilding(BuilderType type, BigInteger serial) {
        assertThatIllegalArgumentException().isThrownBy(() -> {
            if (type == BuilderType.SELF_SIGNED) {
                PkiCertificate.selfSigned().serialNumber(serial);
            } else {
                PkiCertificate.signed().serialNumber(serial);
            }
        }).withMessageContaining("serialNumber");
    }

    @ParameterizedTest
    @EnumSource(BuilderType.class)
    void nullExplicitSerialIsRejected(BuilderType type) {
        assertThatNullPointerException().isThrownBy(() -> {
            if (type == BuilderType.SELF_SIGNED) {
                PkiCertificate.selfSigned().serialNumber(null);
            } else {
                PkiCertificate.signed().serialNumber(null);
            }
        }).withMessage("serialNumber");
    }

    @Test
    void generationRetriesZeroIncludingAfterClearingTheSignBit() {
        byte[] signBitOnly = new byte[20];
        signBitOnly[0] = (byte) 0x80;
        byte[] allBits = new byte[20];
        Arrays.fill(allBits, (byte) 0xff);
        SequenceRandom random = new SequenceRandom(new byte[20], signBitOnly, allBits);

        BigInteger serial = CertificateBuildSupport.randomSerial(random);

        assertThat(serial).isEqualTo(BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE));
        assertThat(random.calls).isEqualTo(3);
    }

    @Test
    void generationPreservesTheSmallestNonzeroSerial() {
        byte[] one = new byte[20];
        one[19] = 1;
        SequenceRandom random = new SequenceRandom(one);

        assertThat(CertificateBuildSupport.randomSerial(random)).isEqualTo(BigInteger.ONE);
        assertThat(random.calls).isOne();
    }

    private static Stream<Arguments> validSerials() {
        return Stream.of(BuilderType.values()).flatMap(type -> Stream.of(
                Arguments.of(type, BigInteger.ONE, 1),
                Arguments.of(type, BigInteger.valueOf(127), 1),
                Arguments.of(type, BigInteger.valueOf(128), 2),
                Arguments.of(type, BigInteger.ONE.shiftLeft(151).subtract(BigInteger.ONE), 19),
                Arguments.of(type, BigInteger.ONE.shiftLeft(151), 20),
                Arguments.of(type, BigInteger.ONE.shiftLeft(158), 20),
                Arguments.of(type, BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE), 20)));
    }

    private static Stream<Arguments> invalidSerials() {
        return Stream.of(BuilderType.values()).flatMap(type -> Stream.of(
                BigInteger.ZERO,
                BigInteger.ONE.negate(),
                BigInteger.ONE.shiftLeft(159).negate(),
                BigInteger.ONE.shiftLeft(159),
                BigInteger.ONE.shiftLeft(160).subtract(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(160))
                .map(serial -> Arguments.of(type, serial)));
    }

    private static int serialDerValueLength(X509Certificate certificate) throws Exception {
        ASN1Integer serial = Certificate.getInstance(certificate.getEncoded())
                .getTBSCertificate().getSerialNumber();
        byte[] der = serial.getEncoded(ASN1Encoding.DER);
        assertThat(der[0]).isEqualTo((byte) 0x02); // INTEGER tag.
        int valueLength = Byte.toUnsignedInt(der[1]);
        assertThat(valueLength).isLessThan(128); // These serials use short-form DER lengths.
        assertThat(der.length).isEqualTo(2 + valueLength);
        assertThat(serial.getValue()).isEqualTo(certificate.getSerialNumber());
        return valueLength;
    }

    private static SelfSignedCertificateBuilder selfSigned() {
        return PkiCertificate.selfSigned()
                .subject("CN=Serial Test Self-Signed")
                .keyPair(subjectKeys)
                .validFor(Duration.ofDays(1));
    }

    private static SignedCertificateBuilder signed() {
        return PkiCertificate.signed()
                .subject("CN=Serial Test Issued")
                .keyPair(subjectKeys)
                .issuer(issuer, issuerKeys.getPrivate())
                .validFor(Duration.ofDays(1));
    }

    private enum BuilderType {
        SELF_SIGNED, SIGNED
    }

    private static final class SequenceRandom extends SecureRandom {
        @Serial
        private static final long serialVersionUID = 1L;

        private final byte[][] values;
        private int calls;

        private SequenceRandom(byte[]... values) {
            this.values = values;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            assertThat(calls).isLessThan(values.length);
            assertThat(bytes).hasSize(values[calls].length);
            System.arraycopy(values[calls], 0, bytes, 0, bytes.length);
            calls++;
        }
    }
}
