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

/**
 * Fluent entry point for issuing X.509 Certificate Revocation Lists (CRLs).
 *
 * <pre>{@code
 * X509CRL crl = PkiCrl.issued()
 *     .issuer(caCert, caPrivateKey)
 *     .nextUpdate(Duration.ofHours(24))
 *     .revoke(leafCert1, RevocationReason.KEY_COMPROMISE)
 *     .revoke(leafCert2, RevocationReason.PRIVILEGE_WITHDRAWN)
 *     .build();
 * }</pre>
 */
public final class PkiCrl {

    private PkiCrl() {
        // Entry-point class — not instantiable.
    }

    /** Starts a new CRL issuance builder. */
    public static CrlBuilder issued() {
        return new CrlBuilder();
    }
}
