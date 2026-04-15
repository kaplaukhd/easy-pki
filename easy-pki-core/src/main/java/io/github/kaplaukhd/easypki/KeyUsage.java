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
 * Individual flags of the X.509 {@code KeyUsage} extension (RFC 5280 §4.2.1.3).
 *
 * <p>Pass one or more values to a certificate builder's {@code keyUsage(...)}
 * method to restrict what operations the certificate's key may be used for.
 */
public enum KeyUsage {

    /** Signing of data other than certificates or CRLs. */
    DIGITAL_SIGNATURE(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature),

    /**
     * Non-repudiation / content commitment — signing with intent that the
     * signer cannot later deny having made the signature.
     */
    NON_REPUDIATION(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation),

    /** Enciphering symmetric keys — used in RSA-based TLS key exchange. */
    KEY_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment),

    /** Direct encipherment of raw user data (rarely used). */
    DATA_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment),

    /** Used in key-agreement protocols such as (EC)DH. */
    KEY_AGREEMENT(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement),

    /** Signing of other certificates — mandatory for CA keys. */
    KEY_CERT_SIGN(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),

    /** Signing of CRLs — typically set alongside {@link #KEY_CERT_SIGN} on CAs. */
    CRL_SIGN(org.bouncycastle.asn1.x509.KeyUsage.cRLSign),

    /** Restricts {@link #KEY_AGREEMENT} to enciphering only. */
    ENCIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly),

    /** Restricts {@link #KEY_AGREEMENT} to deciphering only. */
    DECIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);

    private final int bcBit;

    KeyUsage(int bcBit) {
        this.bcBit = bcBit;
    }

    int bcBit() {
        return bcBit;
    }
}
