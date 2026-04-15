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
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class PkiKeysTest {

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072, 4096})
    void rsa_generatesKeyPairOfExpectedSize(int bits) {
        KeyPair pair = PkiKeys.rsa(bits);

        assertThat(pair.getPublic()).isInstanceOf(RSAPublicKey.class);
        assertThat(pair.getPrivate()).isInstanceOf(RSAPrivateKey.class);
        assertThat(((RSAPublicKey) pair.getPublic()).getModulus().bitLength())
                .isEqualTo(bits);
        assertThat(pair.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void rsa_usesPublicExponentF4() {
        KeyPair pair = PkiKeys.rsa(2048);

        assertThat(((RSAPublicKey) pair.getPublic()).getPublicExponent())
                .isEqualTo(java.math.BigInteger.valueOf(65537));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 512, 1024, 2047, -1})
    void rsa_rejectsKeysBelowMinimumSize(int bits) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> PkiKeys.rsa(bits))
                .withMessageContaining(String.valueOf(PkiKeys.MIN_RSA_KEY_SIZE));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void ec_generatesKeyPairForEachSupportedCurve(Curve curve) {
        KeyPair pair = PkiKeys.ec(curve);

        assertThat(pair.getPublic()).isInstanceOf(ECPublicKey.class);
        assertThat(pair.getPrivate()).isInstanceOf(ECPrivateKey.class);
        assertThat(pair.getPublic().getAlgorithm()).isEqualTo("EC");

        int orderBitLength = ((ECPublicKey) pair.getPublic()).getParams().getOrder().bitLength();
        assertThat(orderBitLength).isEqualTo(curve.fieldSize());
    }

    @Test
    void ec_rejectsNullCurve() {
        assertThatNullPointerException()
                .isThrownBy(() -> PkiKeys.ec(null))
                .withMessageContaining("curve");
    }

    @Test
    void rsa_generatesDistinctKeysOnEachCall() {
        KeyPair first = PkiKeys.rsa(2048);
        KeyPair second = PkiKeys.rsa(2048);

        assertThat(first.getPrivate()).isNotEqualTo(second.getPrivate());
        assertThat(first.getPublic()).isNotEqualTo(second.getPublic());
    }
}
