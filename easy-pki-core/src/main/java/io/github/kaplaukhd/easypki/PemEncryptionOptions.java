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

import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PKCS8Generator;

/**
 * Immutable PKCS#8 PEM encryption parameters: PBES2, PBKDF2 and AES-256-CBC.
 * No password is retained. Fresh random salt and IV are generated for each write.
 *
 * @param iterations positive PBKDF2 iteration count; defaults to 600,000
 * @param prf PBKDF2 pseudorandom function; defaults to HMAC-SHA-256
 */
public record PemEncryptionOptions(int iterations, Prf prf) {
    /** Validates the iteration count and PRF. Lower costs weaken password protection. */
    public PemEncryptionOptions {
        if (iterations <= 0) throw new IllegalArgumentException("iterations must be positive");
        Objects.requireNonNull(prf, "prf");
    }

    /** The default writing policy; callers may tune cost for their environment. */
    public static PemEncryptionOptions defaults() {
        return new PemEncryptionOptions(600_000, Prf.HMAC_SHA256);
    }

    /** Supported PRFs for new encrypted PEM output. Legacy PRFs remain readable. */
    public enum Prf {
        /** PBKDF2 with HMAC-SHA-256. */
        HMAC_SHA256(PKCS8Generator.PRF_HMACSHA256),
        /** PBKDF2 with HMAC-SHA-512. */
        HMAC_SHA512(PKCS8Generator.PRF_HMACSHA512);

        private final AlgorithmIdentifier identifier;
        Prf(AlgorithmIdentifier identifier) { this.identifier = identifier; }
        AlgorithmIdentifier identifier() { return identifier; }
    }
}
