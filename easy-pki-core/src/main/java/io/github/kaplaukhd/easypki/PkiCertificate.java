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
     * Alternatively, supply a public key and external {@link PkiSigner} via
     * {@link SelfSignedCertificateBuilder#signer(java.security.PublicKey, PkiSigner)}.
     */
    public static SelfSignedCertificateBuilder selfSigned() {
        return new SelfSignedCertificateBuilder();
    }

    /**
     * Starts a new builder for a certificate signed by another CA. The issuer
     * certificate and its private key are supplied via
     * {@link SignedCertificateBuilder#issuer(java.security.cert.X509Certificate,
     * java.security.PrivateKey)}.
     * An external signing operation can be supplied through
     * {@link SignedCertificateBuilder#issuer(java.security.cert.X509Certificate, PkiSigner)}.
     */
    public static SignedCertificateBuilder signed() {
        return new SignedCertificateBuilder();
    }
    /** Starts the Root CA issuance profile (self-signed, keyCertSign/cRLSign). */
    public static SelfSignedCertificateBuilder rootCa() {
        return selfSigned().profile(CertificateProfile.ROOT_CA);
    }

    /** Starts the Intermediate CA profile; requires issuer(PkiIdentity), default pathLength=0. */
    public static SignedCertificateBuilder intermediateCa() {
        return signed().profile(CertificateProfile.INTERMEDIATE_CA);
    }

    /** Starts the TLS server profile; requires an issuer identity and explicit DNS/IP SAN. */
    public static SignedCertificateBuilder tlsServer() {
        return signed().profile(CertificateProfile.TLS_SERVER);
    }

    /** Starts the TLS client profile; requires an issuer identity and explicit client identity. */
    public static SignedCertificateBuilder tlsClient() {
        return signed().profile(CertificateProfile.TLS_CLIENT);
    }

}
