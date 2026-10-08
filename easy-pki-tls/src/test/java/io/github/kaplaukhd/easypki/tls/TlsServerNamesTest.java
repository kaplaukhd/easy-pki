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
package io.github.kaplaukhd.easypki.tls;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TlsServerNamesTest {
    private static final KeyPair KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate SERVER = PkiCertificate.selfSigned()
            .subject("CN=cn-only.example.test").keyPair(KEYS).validFor(Duration.ofDays(1))
            .san(names -> names.dns("www.example.test").dns("*.service.example.test")
                    .dns("xn--bcher-kva.example").dns("w*.invalid.example.test")
                    .ip("192.0.2.1").ip("2001:db8::1").ip("::ffff:192.0.2.2")).build();

    @ParameterizedTest
    @ValueSource(strings = {"www.example.test", "WWW.EXAMPLE.TEST", "www.example.test.",
            "one.service.example.test", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE",
            "192.0.2.1", "2001:db8:0:0:0:0:0:1", "[2001:db8::1]", "::ffff:192.0.2.2"})
    void matchesDnsWildcardAlabelAndExactIpSans(String reference) {
        assertThatCode(() -> TlsServerNames.requireMatch(SERVER, reference)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"cn-only.example.test", "other.example.test", "service.example.test",
            "two.one.service.example.test", "www.invalid.example.test", "bücher.example",
            "192.0.2.2", "::ffff:192.0.2.1", "2001:db8::2", "192.00.2.1", "127.1", "2130706433",
            "[www.example.test]", "www.example.test:443", "https://www.example.test", "www.example.test..",
            "*.service.example.test", " www.example.test", "www.example.test\n", "", "2001:db8::1%eth0"})
    void rejectsWrongUnsupportedAndAmbiguousReferenceNames(String reference) {
        assertThatThrownBy(() -> TlsServerNames.requireMatch(SERVER, reference)).isInstanceOf(CertificateException.class);
    }

    @Test
    void neverFallsBackToCommonNameAndRequiresAReference() {
        X509Certificate cnOnly = PkiCertificate.selfSigned().subject("CN=www.example.test").keyPair(KEYS)
                .validFor(Duration.ofDays(1)).build();
        assertThatThrownBy(() -> TlsServerNames.requireMatch(cnOnly, "www.example.test"))
                .isInstanceOf(CertificateException.class).hasMessageContaining("subjectAltName");
        assertThatThrownBy(() -> TlsServerNames.requireMatch(SERVER, null)).isInstanceOf(CertificateException.class);
    }

    @Test
    void dnsSanContainingAnIpLiteralDoesNotBecomeAnIpIdentifier() {
        X509Certificate dnsIp = PkiCertificate.selfSigned().subject("CN=Test").keyPair(KEYS)
                .validFor(Duration.ofDays(1)).san(names -> names.dns("192.0.2.1")).build();
        assertThatThrownBy(() -> TlsServerNames.requireMatch(dnsIp, "192.0.2.1")).isInstanceOf(CertificateException.class);
    }

    @Test
    void rejectsMalformedExplicitIpSanTagsInsteadOfNormalizingThem() throws Exception {
        byte[] malformed = new DERSequence(new DERTaggedObject(true, GeneralName.iPAddress,
                new DEROctetString(new byte[] {(byte) 192, 0, 2, 1}))).getEncoded();
        X509Certificate certificate = withEncodedSan(malformed);
        assertThatThrownBy(() -> TlsServerNames.requireMatch(certificate, "192.0.2.1"))
                .isInstanceOf(CertificateException.class).hasMessageContaining("canonical DER");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "0500", "3000", "3080"})
    void malformedOrEmptySanValuesFailWithCertificateException(String hex) throws Exception {
        X509Certificate certificate = withEncodedSan(java.util.HexFormat.of().parseHex(hex));
        assertThatThrownBy(() -> TlsServerNames.requireMatch(certificate, "192.0.2.1"))
                .isInstanceOf(CertificateException.class);
    }

    private static X509Certificate withEncodedSan(byte[] encoded) throws Exception {
        Date before = new Date(System.currentTimeMillis() - 1000);
        Date after = new Date(System.currentTimeMillis() + 60_000);
        var builder = new JcaX509v3CertificateBuilder(new X500Principal("CN=Malformed"), BigInteger.ONE,
                before, after, new X500Principal("CN=Malformed"), KEYS.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, encoded);
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(KEYS.getPrivate())));
    }
}
