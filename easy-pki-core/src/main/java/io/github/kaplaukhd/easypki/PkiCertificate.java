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

/**
 * Fluent entry point for building X.509 certificates.
 *
 * <h2>Self-signed (root CA or local cert)</h2>
 * <pre>{@code
 * X509Certificate root = PkiCertificate.selfSigned()
 *     .subject("CN=My Root CA, O=Corp, C=RU")
 *     .keyPair(rootKeys)
 *     .validFor(Duration.ofDays(3650))
 *     .isCA(true)
 *     .pathLength(1)
 *     .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
 *     .build();
 * }</pre>
 */
public final class PkiCertificate {

    private PkiCertificate() {
        // Entry-point class — not instantiable.
    }

    /**
     * Starts a new self-signed certificate builder. The same key pair is used
     * both as the certificate's public key and to sign the resulting certificate.
     */
    public static SelfSignedCertificateBuilder selfSigned() {
        return new SelfSignedCertificateBuilder();
    }

    /**
     * Starts a new builder for a certificate signed by another CA. The issuer
     * certificate and its private key are supplied via
     * {@link SignedCertificateBuilder#issuer(java.security.cert.X509Certificate,
     * java.security.PrivateKey)}.
     */
    public static SignedCertificateBuilder signed() {
        return new SignedCertificateBuilder();
    }
}
