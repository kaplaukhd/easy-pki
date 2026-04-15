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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PkiCertificatesTest {

    private X509Certificate root;
    private X509Certificate leaf;

    @BeforeEach
    void setUp() {
        KeyPair rootKeys = PkiKeys.rsa(2048);
        root = PkiCertificate.selfSigned()
                .subject("CN=Test Root, O=Acme")
                .keyPair(rootKeys)
                .validFor(Duration.ofDays(365))
                .isCA(true)
                .build();

        KeyPair leafKeys = PkiKeys.rsa(2048);
        leaf = PkiCertificate.signed()
                .subject("CN=leaf.example.org")
                .publicKey(leafKeys.getPublic())
                .issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(30))
                .build();
    }

    @Test
    void pemRoundTripPreservesEncoding() throws Exception {
        String pem = PkiCertificates.toPem(leaf);

        assertThat(pem).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(pem).contains("-----END CERTIFICATE-----");

        X509Certificate decoded = PkiCertificates.fromPem(pem);
        assertThat(decoded.getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(decoded).isEqualTo(leaf);
    }

    @Test
    void derRoundTripPreservesEncoding() throws Exception {
        byte[] der = PkiCertificates.toDer(leaf);

        X509Certificate decoded = PkiCertificates.fromDer(der);
        assertThat(decoded.getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(decoded).isEqualTo(leaf);
    }

    @Test
    void fileRoundTrip(@TempDir Path tmp) throws Exception {
        Path path = tmp.resolve("leaf.crt");

        PkiCertificates.toFile(leaf, path);
        assertThat(Files.readString(path)).contains("BEGIN CERTIFICATE");

        X509Certificate decoded = PkiCertificates.fromFile(path);
        assertThat(decoded.getEncoded()).isEqualTo(leaf.getEncoded());
    }

    @Test
    void chainPemContainsAllCertsInOrder() throws Exception {
        String pem = PkiCertificates.toPem(List.of(leaf, root));

        assertThat(pem.split("-----BEGIN CERTIFICATE-----")).hasSize(3); // 2 certs + empty prefix

        List<X509Certificate> parsed = PkiCertificates.allFromPem(pem);
        assertThat(parsed).hasSize(2);
        assertThat(parsed.get(0).getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(parsed.get(1).getEncoded()).isEqualTo(root.getEncoded());
    }

    @Test
    void chainFileRoundTrip(@TempDir Path tmp) throws Exception {
        Path path = tmp.resolve("chain.pem");

        PkiCertificates.toFile(List.of(leaf, root), path);
        List<X509Certificate> parsed = PkiCertificates.allFromFile(path);

        assertThat(parsed).hasSize(2);
        assertThat(parsed.get(0).getEncoded()).isEqualTo(leaf.getEncoded());
        assertThat(parsed.get(1).getEncoded()).isEqualTo(root.getEncoded());
    }

    @Test
    void emptyPemRejected() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiCertificates.fromPem(""))
                .withMessageContaining("No PEM");
    }

    @Test
    void garbagePemRejected() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiCertificates.fromPem("not a PEM at all"));
    }

    @Test
    void malformedDerRejected() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiCertificates.fromDer(new byte[]{1, 2, 3}));
    }

    @Test
    void allFromPemOnEmptyInputThrows() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiCertificates.allFromPem(""))
                .withMessageContaining("No certificates");
    }

    @Test
    void pemWithNonCertificateObjectRejected() {
        KeyPair keys = PkiKeys.rsa(2048);
        String keyPem = PkiPrivateKeys.toPem(keys.getPrivate());

        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiCertificates.fromPem(keyPem))
                .withMessageContaining("Expected an X.509 certificate");
    }
}
