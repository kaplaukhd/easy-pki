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
package io.github.kaplaukhd.easypki.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PkiCrlTest {

    private KeyPair caKeys;
    private X509Certificate caCert;

    @BeforeEach
    void setUp() {
        caKeys = PkiKeys.rsa(2048);
        caCert = PkiCertificate.selfSigned()
                .subject("CN=Test CA")
                .keyPair(caKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();
    }

    @Test
    void emptyCrlIsValid() throws Exception {
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofDays(1))
                .build();

        assertThat(crl.getIssuerX500Principal()).isEqualTo(caCert.getSubjectX500Principal());
        crl.verify(caCert.getPublicKey());
        assertThat(crl.getRevokedCertificates()).isNullOrEmpty();
    }

    @Test
    void revokedCertAppearsWithCorrectReason() throws Exception {
        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(caCert, caKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(leaf, RevocationReason.KEY_COMPROMISE)
                .build();

        X509CRLEntry entry = crl.getRevokedCertificate(leaf);
        assertThat(entry).isNotNull();
        assertThat(entry.getSerialNumber()).isEqualTo(leaf.getSerialNumber());
        assertThat(entry.getRevocationReason())
                .isEqualTo(java.security.cert.CRLReason.KEY_COMPROMISE);
    }

    @Test
    void multipleRevocationsAreRecorded() throws Exception {
        KeyPair keysA = PkiKeys.rsa(2048);
        KeyPair keysB = PkiKeys.rsa(2048);
        X509Certificate a = PkiCertificate.signed()
                .subject("CN=a").publicKey(keysA.getPublic())
                .issuer(caCert, caKeys.getPrivate())
                .validFor(Duration.ofDays(30)).build();
        X509Certificate b = PkiCertificate.signed()
                .subject("CN=b").publicKey(keysB.getPublic())
                .issuer(caCert, caKeys.getPrivate())
                .validFor(Duration.ofDays(30)).build();

        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .revoke(a, RevocationReason.KEY_COMPROMISE)
                .revoke(b, RevocationReason.SUPERSEDED)
                .build();

        assertThat(crl.getRevokedCertificates()).hasSize(2);
        assertThat(crl.getRevokedCertificate(a)).isNotNull();
        assertThat(crl.getRevokedCertificate(b)).isNotNull();
    }

    @Test
    void revokeBySerialOnly() throws Exception {
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofDays(1))
                .revoke(BigInteger.valueOf(42), RevocationReason.CA_COMPROMISE)
                .build();

        X509CRLEntry entry = crl.getRevokedCertificate(BigInteger.valueOf(42));
        assertThat(entry).isNotNull();
    }

    @Test
    void explicitCrlNumberIsPreserved() {
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofDays(1))
                .crlNumber(BigInteger.valueOf(7))
                .build();

        // OID 2.5.29.20 = CRLNumber
        assertThat(crl.getExtensionValue("2.5.29.20")).isNotNull();
    }

    @Test
    void explicitThisAndNextUpdateAreHonoured() {
        Instant t = Instant.parse("2030-06-01T00:00:00Z");
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .thisUpdate(t)
                .nextUpdate(t.plus(Duration.ofDays(7)))
                .build();

        assertThat(crl.getThisUpdate().toInstant()).isEqualTo(t);
        assertThat(crl.getNextUpdate().toInstant()).isEqualTo(t.plus(Duration.ofDays(7)));
    }

    @Test
    void missingIssuerRejected() {
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCrl.issued().nextUpdate(Duration.ofDays(1)).build())
                .withMessageContaining("issuer");
    }

    @Test
    void missingNextUpdateRejected() {
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCrl.issued().issuer(caCert, caKeys.getPrivate()).build())
                .withMessageContaining("nextUpdate");
    }

    @Test
    void nonPositiveNextUpdateDurationRejected() {
        assertThatIllegalArgumentException().isThrownBy(() ->
                PkiCrl.issued().nextUpdate(Duration.ZERO));
    }

    @Test
    void pemAndDerRoundTrip() throws Exception {
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        String pem = PkiCrls.toPem(crl);
        assertThat(pem).contains("BEGIN X509 CRL");
        X509CRL fromPem = PkiCrls.fromPem(pem);
        assertThat(fromPem.getEncoded()).isEqualTo(crl.getEncoded());

        byte[] der = PkiCrls.toDer(crl);
        X509CRL fromDer = PkiCrls.fromDer(der);
        assertThat(fromDer.getEncoded()).isEqualTo(crl.getEncoded());
    }

    @Test
    void fileRoundTripPem(@TempDir Path tmp) {
        X509CRL crl = PkiCrl.issued()
                .issuer(caCert, caKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();
        Path path = tmp.resolve("ca.crl.pem");
        PkiCrls.toFile(crl, path);

        X509CRL loaded = PkiCrls.fromFile(path);
        assertThat(loaded.getIssuerX500Principal()).isEqualTo(crl.getIssuerX500Principal());
    }

    @Test
    void ecIssuerSignsCrl() throws Exception {
        KeyPair ecKeys = PkiKeys.ec(io.github.kaplaukhd.easypki.Curve.P_256);
        X509Certificate ecCa = PkiCertificate.selfSigned()
                .subject("CN=EC CA").keyPair(ecKeys)
                .validFor(Duration.ofDays(365)).isCA(true).build();

        X509CRL crl = PkiCrl.issued()
                .issuer(ecCa, ecKeys.getPrivate())
                .nextUpdate(Duration.ofHours(24))
                .build();

        assertThat(crl.getSigAlgName()).isEqualToIgnoringCase("SHA256withECDSA");
        crl.verify(ecCa.getPublicKey());
    }
}
