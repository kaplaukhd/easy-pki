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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;

/**
 * Signs certificate data without exposing or exporting a private key.
 * Implementations can use a JCA key handle, an HSM or an external service.
 *
 * <p>The algorithm name must have a known X.509 AlgorithmIdentifier in the
 * bundled Bouncy Castle implementation. The signer must use that algorithm's
 * parameters and signature encoding: for example, ECDSA returns DER-encoded
 * (r, s), not a raw concatenation. Configurable algorithm parameters are not
 * part of this contract yet.
 *
 * <p>Builders provide the complete DER-encoded TBSCertificate, not a digest.
 * Implementations own hashing and signing, must use the intended signing key,
 * and must keep their algorithm stable. A signer may be reused across builds;
 * its implementation defines concurrency and backend-resource lifetime.
 * Builders never close a backend, destroy a key, or call PrivateKey.getEncoded().
 */
public interface PkiSigner {
    /** Returns a stable signature algorithm name, for example {@code SHA256withRSA}. */
    String signatureAlgorithm();

    /**
     * Signs the supplied complete message and returns its raw X.509 signature
     * bytes, without a CMS or certificate wrapper. Each call is independent.
     *
     * @param content complete data to sign, not a precomputed digest
     * @return nonempty signature bytes in the declared algorithm's encoding
     * @throws GeneralSecurityException if the backend cannot produce a signature
     */
    byte[] sign(byte[] content) throws GeneralSecurityException;

    /** Uses the existing RSA/EC SHA-256 defaults and normal JCA provider selection. */
    static PkiSigner jca(PrivateKey key) {
        Objects.requireNonNull(key, "key");
        return jca(key, CertificateBuildSupport.defaultSignatureAlgorithm(key));
    }

    /** Uses the given algorithm and normal JCA provider selection. */
    static PkiSigner jca(PrivateKey key, String algorithm) {
        return new JcaPkiSigner(key, algorithm, null);
    }

    /**
     * Uses only the supplied provider instance; it need not be globally registered.
     * Unsupported algorithms or key handles fail without falling back to another provider.
     */
    static PkiSigner jca(PrivateKey key, String algorithm, Provider provider) {
        return new JcaPkiSigner(key, algorithm, Objects.requireNonNull(provider, "provider"));
    }

    /**
     * Resolves a registered provider by name once, retaining that instance.
     * Never registers a provider or silently falls back to normal selection.
     *
     * @throws IllegalArgumentException if no such provider is registered
     */
    static PkiSigner jca(PrivateKey key, String algorithm, String providerName) {
        Objects.requireNonNull(providerName, "providerName");
        Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            throw new IllegalArgumentException("No registered JCA provider named '" + providerName + "'");
        }
        return jca(key, algorithm, provider);
    }
}
