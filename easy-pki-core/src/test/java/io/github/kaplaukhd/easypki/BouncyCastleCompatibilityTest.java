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

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Reads frozen synthetic artifacts produced before the Bouncy Castle upgrade. */
class BouncyCastleCompatibilityTest {

    private static final String FIXTURES = "/compatibility/bc-1.78.1/";
    private static final String PASSWORD = "synthetic-fixture-password";

    @ParameterizedTest
    @CsvSource({
            "rsa-root, RSA, 1.2.840.113549.1.1.11, 178101",
            "ec-root, EC, 1.2.840.10045.4.3.2, 178102"
    })
    void readsOldPemAndDerCertificatesWithValidJcaSignatures(
            String fixture, String keyAlgorithm, String signatureOid, long serial) throws Exception {
        byte[] der = resource(fixture + ".der");
        X509Certificate fromPem = PkiCertificates.fromPem(text(fixture + ".pem"));
        X509Certificate fromDer = PkiCertificates.fromDer(der);

        for (X509Certificate certificate : new X509Certificate[]{fromPem, fromDer}) {
            assertThat(certificate.getEncoded()).isEqualTo(der);
            assertThat(certificate.getPublicKey().getAlgorithm()).isEqualTo(keyAlgorithm);
            assertThat(certificate.getSigAlgOID()).isEqualTo(signatureOid);
            assertThat(certificate.getSerialNumber()).isEqualTo(BigInteger.valueOf(serial));
            assertThat(certificate.getNotBefore().toInstant())
                    .isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));
            assertThat(certificate.getNotAfter().toInstant())
                    .isEqualTo(Instant.parse("2044-01-01T00:00:00Z"));
            // Standard JCA verification also exercises the old signature encoding.
            certificate.verify(certificate.getPublicKey());
        }
    }

    @ParameterizedTest
    @CsvSource({"rsa-root, RSA", "ec-root, EC"})
    void decryptsOldPkcs8PemIntoUsableJcaKeys(String fixture, String algorithm) throws Exception {
        PrivateKey key = PkiPrivateKeys.fromPem(text(fixture + "-encrypted-key.pem"), PASSWORD);
        X509Certificate certificate = PkiCertificates.fromDer(resource(fixture + ".der"));

        assertThat(key.getAlgorithm()).isEqualTo(algorithm);
        assertSigningKeyMatchesCertificate(key, certificate);
    }

    @Test
    void loadsOldPkcs12IdentityWithUsablePrivateKeyAndOrderedChain() throws Exception {
        Pkcs12Bundle identity = PkiPkcs12.load(resource("rsa-identity.p12"), PASSWORD);
        X509Certificate leaf = identity.getCertificate();
        X509Certificate root = PkiCertificates.fromDer(resource("rsa-root.der"));

        assertThat(identity.getAlias()).isEqualTo("synthetic-identity");
        assertThat(leaf.getSubjectX500Principal().getName())
                .isEqualTo("CN=Synthetic BC 1.78.1 Identity");
        assertThat(leaf.getSerialNumber()).isEqualTo(BigInteger.valueOf(178103));
        assertThat(identity.getChain()).containsExactly(leaf, root);
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(root.getSubjectX500Principal());
        leaf.verify(root.getPublicKey());
        root.verify(root.getPublicKey());
        assertSigningKeyMatchesCertificate(identity.getPrivateKey(), leaf);
    }

    private static void assertSigningKeyMatchesCertificate(PrivateKey key, X509Certificate certificate)
            throws Exception {
        assertThat(key).isNotNull();
        byte[] message = "BC 1.78.1 synthetic compatibility fixture".getBytes(StandardCharsets.UTF_8);
        String algorithm = key.getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(message);
        assertThat(verifier.verify(signature)).isTrue();
    }

    private static String text(String name) throws IOException {
        return new String(resource(name), StandardCharsets.UTF_8);
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream in = BouncyCastleCompatibilityTest.class.getResourceAsStream(FIXTURES + name)) {
            if (in == null) {
                throw new IOException("Missing compatibility fixture: " + name);
            }
            return in.readAllBytes();
        }
    }
}
