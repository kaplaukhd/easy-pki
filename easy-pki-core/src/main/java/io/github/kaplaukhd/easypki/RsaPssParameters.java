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

import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/**
 * Immutable RSA-PSS configuration with independently selected message and MGF1
 * digests. Uses trailer field 1 (the standard {@code 0xbc} trailer byte).
 * Provider support and the salt length's fit with the signing key are checked
 * when signing; unsupported combinations fail without changing parameters.
 *
 * @param digestAlgorithm message digest
 * @param mgfDigestAlgorithm MGF1 digest, which may differ from the message digest
 * @param saltLength salt length in bytes, including zero for no salt
 */
public record RsaPssParameters(HashAlgorithm digestAlgorithm, HashAlgorithm mgfDigestAlgorithm, int saltLength) {
    /** Creates a configuration, rejecting null digests and negative salt lengths. */
    public RsaPssParameters {
        Objects.requireNonNull(digestAlgorithm, "digestAlgorithm");
        Objects.requireNonNull(mgfDigestAlgorithm, "mgfDigestAlgorithm");
        if (saltLength < 0) throw new IllegalArgumentException("RSA-PSS salt length must not be negative");
    }

    /** Returns SHA-256 with MGF1/SHA-256 and a 32-byte salt. */
    public static RsaPssParameters sha256() {
        return new RsaPssParameters(HashAlgorithm.SHA256, HashAlgorithm.SHA256, 32);
    }

    /** Returns the equivalent standard JCA parameters. */
    public PSSParameterSpec toParameterSpec() {
        return new PSSParameterSpec(digestAlgorithm.jcaName(), "MGF1",
                new MGF1ParameterSpec(mgfDigestAlgorithm.jcaName()), saltLength, PSSParameterSpec.TRAILER_FIELD_BC);
    }

    static RsaPssParameters fromParameterSpec(PSSParameterSpec parameters) {
        if (!"MGF1".equalsIgnoreCase(parameters.getMGFAlgorithm())) {
            throw new IllegalArgumentException("RSA-PSS requires MGF1");
        }
        if (!(parameters.getMGFParameters() instanceof MGF1ParameterSpec mgf)) {
            throw new IllegalArgumentException("RSA-PSS requires MGF1ParameterSpec");
        }
        if (parameters.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new IllegalArgumentException("RSA-PSS requires trailer field 1");
        }
        return new RsaPssParameters(digest(parameters.getDigestAlgorithm()),
                digest(mgf.getDigestAlgorithm()), parameters.getSaltLength());
    }

    private static HashAlgorithm digest(String algorithm) {
        for (HashAlgorithm digest : HashAlgorithm.values()) {
            if (digest.jcaName().equalsIgnoreCase(algorithm) || digest.name().equalsIgnoreCase(algorithm)) {
                return digest;
            }
        }
        throw new IllegalArgumentException("Unsupported RSA-PSS digest: " + algorithm);
    }
}
