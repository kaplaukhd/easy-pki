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
 * One reason why a certificate failed validation.
 *
 * @param code    categorisation suitable for programmatic handling
 * @param message human-readable detail
 */
public record ValidationError(Code code, String message) {

    /** Broad categories of validation failure. */
    public enum Code {
        /** The certificate's {@code notAfter} is in the past. */
        EXPIRED,
        /** The certificate's {@code notBefore} is in the future. */
        NOT_YET_VALID,
        /** An issuer/subject DN mismatch in the chain. */
        ISSUER_MISMATCH,
        /** A certificate's signature could not be verified by its alleged issuer. */
        BROKEN_SIGNATURE,
        /** An intermediate in the chain lacks the {@code cA=TRUE} basic constraint. */
        NOT_A_CA,
        /** The chain does not terminate in a trusted root. */
        UNTRUSTED_ROOT,
        /** The chain is empty or missing required certificates. */
        INCOMPLETE_CHAIN,
        /** The certificate has been revoked (reported by OCSP or CRL). */
        REVOKED,
        /** The revocation status of the certificate could not be determined. */
        REVOCATION_UNKNOWN,
        /** OCSP responder was unreachable or returned a malformed response. */
        OCSP_UNAVAILABLE,
        /** A CRL could not be fetched or parsed. */
        CRL_UNAVAILABLE
    }
}
