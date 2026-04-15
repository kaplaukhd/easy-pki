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
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PkiCertificateSignedTest {

    private KeyPair rootKeys;
    private X509Certificate rootCert;

    @BeforeEach
    void setUpRootCa() {
        rootKeys = PkiKeys.rsa(2048);
        rootCert = PkiCertificate.selfSigned()
                .subject("CN=Test Root CA, O=Acme")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(3650))
                .isCA(true)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();
    }

    @Test
    void buildsLeafSignedByRoot() throws Exception {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=api.example.com")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
                .build();

        // Issuer DN should match the root's subject.
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(rootCert.getSubjectX500Principal());
        assertThat(leaf.getSubjectX500Principal().getName()).contains("CN=api.example.com");
        // Signature verifies against the issuer's public key.
        leaf.verify(rootCert.getPublicKey());
        // Default signature algorithm derives from issuer key (RSA).
        assertThat(leaf.getSigAlgName()).isEqualToIgnoringCase("SHA256withRSA");
    }

    @Test
    void keyPairOverloadUsesPublicKey() {
        KeyPair leafKeys = PkiKeys.ec(Curve.P_256);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=ec-leaf")
                .keyPair(leafKeys)
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        assertThat(leaf.getPublicKey().getAlgorithm()).isEqualTo("EC");
        assertThat(leaf.getPublicKey()).isEqualTo(leafKeys.getPublic());
    }

    @Test
    void sanEntriesAreEncoded() throws Exception {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=api.example.com")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .san(s -> s
                        .dns("api.example.com")
                        .dns("*.api.example.com")
                        .ip("10.0.0.1")
                        .email("admin@example.com"))
                .build();

        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertThat(sans).isNotNull().hasSize(4);
        // Entries are lists of (typeInt, value). Type codes from RFC 5280:
        // 1=rfc822Name, 2=dNSName, 7=iPAddress.
        assertThat(sans).anySatisfy(e -> {
            assertThat(e.get(0)).isEqualTo(2);
            assertThat(e.get(1)).isEqualTo("api.example.com");
        });
        assertThat(sans).anySatisfy(e -> {
            assertThat(e.get(0)).isEqualTo(2);
            assertThat(e.get(1)).isEqualTo("*.api.example.com");
        });
        assertThat(sans).anySatisfy(e -> {
            assertThat(e.get(0)).isEqualTo(7);
            assertThat(e.get(1)).isEqualTo("10.0.0.1");
        });
        assertThat(sans).anySatisfy(e -> {
            assertThat(e.get(0)).isEqualTo(1);
            assertThat(e.get(1)).isEqualTo("admin@example.com");
        });
    }

    @Test
    void extendedKeyUsageReflectsRequestedPurposes() throws Exception {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT)
                .build();

        List<String> eku = leaf.getExtendedKeyUsage();
        assertThat(eku).containsExactlyInAnyOrder(
                "1.3.6.1.5.5.7.3.1", // serverAuth
                "1.3.6.1.5.5.7.3.2"  // clientAuth
        );
    }

    @Test
    void crlDistributionPointExtensionIsPresent() {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .crlDistributionPoint("http://crl.example.org/a.crl")
                .crlDistributionPoint("http://crl2.example.org/a.crl")
                .build();

        // OID 2.5.29.31 = cRLDistributionPoints
        assertThat(leaf.getExtensionValue("2.5.29.31")).isNotNull();
    }

    @Test
    void ocspAiaExtensionIsPresent() {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .ocsp("http://ocsp.example.org")
                .build();

        // OID 1.3.6.1.5.5.7.1.1 = authorityInfoAccess
        assertThat(leaf.getExtensionValue("1.3.6.1.5.5.7.1.1")).isNotNull();
    }

    @Test
    void intermediateCaChainsToRoot() throws Exception {
        KeyPair intermediateKeys = PkiKeys.rsa(2048);
        X509Certificate intermediate = PkiCertificate.signed()
                .subject("CN=Intermediate CA")
                .publicKey(intermediateKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1825))
                .pathLength(0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        assertThat(intermediate.getBasicConstraints()).isEqualTo(0);
        intermediate.verify(rootCert.getPublicKey());

        // Build a leaf signed by the intermediate — three-cert chain.
        KeyPair leafKeys = PkiKeys.rsa(2048);
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(intermediate, intermediateKeys.getPrivate())
                .validFor(Duration.ofDays(365))
                .build();

        assertThat(leaf.getIssuerX500Principal()).isEqualTo(intermediate.getSubjectX500Principal());
        leaf.verify(intermediate.getPublicKey());
    }

    @Test
    void ecIssuerProducesEcdsaSignature() throws Exception {
        KeyPair ecRootKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate ecRoot = PkiCertificate.selfSigned()
                .subject("CN=EC Root")
                .keyPair(ecRootKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();

        KeyPair leafKeys = PkiKeys.rsa(2048); // mixed: RSA leaf under EC CA
        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=mixed-leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(ecRoot, ecRootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        assertThat(leaf.getSigAlgName()).isEqualToIgnoringCase("SHA256withECDSA");
        leaf.verify(ecRoot.getPublicKey());
    }

    @Test
    void skiDerivesFromSubjectKeyAndAkiFromIssuerKey() {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();

        assertThat(leaf.getExtensionValue("2.5.29.14")).as("SKI present").isNotNull();
        assertThat(leaf.getExtensionValue("2.5.29.35")).as("AKI present").isNotNull();
    }

    @Test
    void missingIssuerRejected() {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        assertThatIllegalStateException().isThrownBy(() ->
                PkiCertificate.signed()
                        .subject("CN=leaf")
                        .publicKey(leafKeys.getPublic())
                        .validFor(Duration.ofDays(30))
                        .build())
                .withMessageContaining("issuer");
    }

    @Test
    void missingPublicKeyRejected() {
        assertThatIllegalStateException().isThrownBy(() ->
                PkiCertificate.signed()
                        .subject("CN=leaf")
                        .issuer(rootCert, rootKeys.getPrivate())
                        .validFor(Duration.ofDays(30))
                        .build())
                .withMessageContaining("publicKey");
    }

    @Test
    void sanAccumulatesAcrossMultipleCalls() throws Exception {
        KeyPair leafKeys = PkiKeys.rsa(2048);

        X509Certificate leaf = PkiCertificate.signed()
                .subject("CN=leaf")
                .publicKey(leafKeys.getPublic())
                .issuer(rootCert, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .san(s -> s.dns("first.example.org"))
                .san(s -> s.dns("second.example.org"))
                .build();

        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertThat(sans).hasSize(2);
    }
}
