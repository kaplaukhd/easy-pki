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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.bouncycastle.cert.X509CRLHolder;

/** Shared helpers for CRL construction. Package-private. */
final class CrlBuildSupport {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CRL_NUMBER_BYTES = 16;

    private CrlBuildSupport() {
        // Utility class.
    }

    /** Positive random CRL number (20 octets is the upper bound; 16 is plenty and fits quickly). */
    static BigInteger randomCrlNumber() {
        byte[] bytes = new byte[CRL_NUMBER_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return new BigInteger(1, bytes);
    }

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

    static X509CRL toX509Crl(X509CRLHolder holder) throws IOException, CRLException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream in = new ByteArrayInputStream(holder.getEncoded())) {
            return (X509CRL) cf.generateCRL(in);
        }
    }
}
