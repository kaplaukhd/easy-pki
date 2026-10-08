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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Shared helpers used by the certificate builders. Package-private — not part
 * of the public API.
 */
final class CertificateBuildSupport {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SERIAL_NUMBER_BITS = 159;

    private CertificateBuildSupport() {
        // Utility class.
    }

    /**
     * Generates a fresh random, nonzero positive serial number whose DER
     * INTEGER value fits in 20 octets (RFC 5280 §4.1.2.2).
     */
    static BigInteger randomSerial() {
        return randomSerial(SECURE_RANDOM);
    }

    static BigInteger randomSerial(SecureRandom random) {
        BigInteger serial;
        do {
            // Reserve the sign bit so DER never needs a 21st value octet.
            serial = new BigInteger(SERIAL_NUMBER_BITS, random);
        } while (serial.signum() == 0);
        return serial;
    }

    static BigInteger validateSerialNumber(BigInteger serialNumber) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        if (serialNumber.signum() <= 0) {
            throw new IllegalArgumentException(
                    "serialNumber must be positive, got " + serialNumber);
        }
        if (serialNumber.bitLength() > SERIAL_NUMBER_BITS) {
            throw new IllegalArgumentException(
                    "serialNumber must be at most 159 bits (20 DER value octets), got "
                            + serialNumber.bitLength() + " bits");
        }
        return serialNumber;
    }

    /**
     * Returns the default JCA signature algorithm name for a given signing key
     * (RSA → {@code SHA256withRSA}, EC → {@code SHA256withECDSA}).
     *
     * @throws IllegalStateException if the algorithm is unsupported.
     */
    static String defaultSignatureAlgorithm(Key signingKey) {
        String keyAlg = signingKey.getAlgorithm();
        return switch (keyAlg) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> throw new IllegalStateException(
                    "No default signature algorithm for key type '" + keyAlg
                            + "'. Set one explicitly via signatureAlgorithm(...).");
        };
    }

    /** Converts a BouncyCastle {@link X509CertificateHolder} to a standard JCA certificate. */
    static X509Certificate toX509Certificate(X509CertificateHolder holder)
            throws IOException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream in = new ByteArrayInputStream(holder.getEncoded())) {
            return (X509Certificate) cf.generateCertificate(in);
        }
    }
}
