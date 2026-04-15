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
 * Hash algorithms supported by {@link PkiCertInfo#getFingerprint(HashAlgorithm)}.
 */
public enum HashAlgorithm {

    /** SHA-1 — included for compatibility; cryptographically weak. */
    SHA1("SHA-1"),

    /** SHA-256 — recommended default. */
    SHA256("SHA-256"),

    /** SHA-384. */
    SHA384("SHA-384"),

    /** SHA-512. */
    SHA512("SHA-512");

    private final String jcaName;

    HashAlgorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    /** Returns the standard JCA algorithm name (e.g. {@code "SHA-256"}). */
    public String jcaName() {
        return jcaName;
    }
}
