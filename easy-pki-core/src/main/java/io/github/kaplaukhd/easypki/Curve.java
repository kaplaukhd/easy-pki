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
 * Named elliptic curves supported by {@link PkiKeys#ec(Curve)}.
 *
 * <p>The curves follow the NIST recommendations and map to the standard names
 * recognised by the JCA (e.g. {@code secp256r1}).
 */
public enum Curve {

    /** NIST P-256 (also known as {@code secp256r1} / {@code prime256v1}). 128-bit security. */
    P_256("secp256r1", 256),

    /** NIST P-384 (also known as {@code secp384r1}). 192-bit security. */
    P_384("secp384r1", 384),

    /** NIST P-521 (also known as {@code secp521r1}). 256-bit security. */
    P_521("secp521r1", 521);

    private final String standardName;
    private final int fieldSize;

    Curve(String standardName, int fieldSize) {
        this.standardName = standardName;
        this.fieldSize = fieldSize;
    }

    /**
     * Returns the standard curve name recognised by the JCA,
     * e.g. {@code "secp256r1"}.
     */
    public String standardName() {
        return standardName;
    }

    /**
     * Returns the size of the underlying field in bits (e.g. {@code 256} for {@link #P_256}).
     */
    public int fieldSize() {
        return fieldSize;
    }
}
