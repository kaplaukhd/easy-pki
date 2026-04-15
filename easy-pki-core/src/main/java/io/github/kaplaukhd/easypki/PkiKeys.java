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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Key pair generation for RSA and elliptic-curve keys.
 *
 * <p>All operations go through the BouncyCastle provider without registering it
 * in the global JCA provider list, so using this library never mutates the
 * host application's security configuration.
 *
 * <h2>Examples</h2>
 * <pre>{@code
 * KeyPair rsa2048 = PkiKeys.rsa(2048);
 * KeyPair rsa4096 = PkiKeys.rsa(4096);
 * KeyPair ecP256  = PkiKeys.ec(Curve.P_256);
 * }</pre>
 */
public final class PkiKeys {

    /**
     * Minimum accepted RSA key size in bits. Values below this are rejected
     * because shorter RSA keys are no longer considered secure by NIST SP 800-57
     * and are deprecated in modern TLS profiles.
     */
    public static final int MIN_RSA_KEY_SIZE = 2048;

    private static final Provider BC = new BouncyCastleProvider();

    private PkiKeys() {
        // Utility class — not instantiable.
    }

    /**
     * Generates a fresh RSA key pair with public exponent {@code F4} ({@code 65537}).
     *
     * @param bits key size in bits; must be at least {@value #MIN_RSA_KEY_SIZE}.
     *             Common values: {@code 2048}, {@code 3072}, {@code 4096}.
     * @return a newly generated RSA key pair.
     * @throws IllegalArgumentException if {@code bits} is below {@value #MIN_RSA_KEY_SIZE}.
     */
    public static KeyPair rsa(int bits) {
        if (bits < MIN_RSA_KEY_SIZE) {
            throw new IllegalArgumentException(
                    "RSA key size must be at least " + MIN_RSA_KEY_SIZE
                            + " bits, got " + bits);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BC);
            generator.initialize(
                    new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4),
                    new SecureRandom());
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Failed to generate RSA key pair of " + bits + " bits", e);
        }
    }

    /**
     * Generates a fresh elliptic-curve key pair on the given named curve.
     *
     * @param curve the named curve; must not be {@code null}.
     * @return a newly generated EC key pair.
     * @throws NullPointerException if {@code curve} is {@code null}.
     */
    public static KeyPair ec(Curve curve) {
        Objects.requireNonNull(curve, "curve");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC);
            generator.initialize(
                    new ECGenParameterSpec(curve.standardName()),
                    new SecureRandom());
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Failed to generate EC key pair for curve " + curve, e);
        }
    }
}
