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
package io.github.kaplaukhd.easypki.spring;

/**
 * Revocation-checking mode selected via the
 * {@code easy-pki.validation.mode} property.
 */
public enum ValidationMode {
    /** No revocation checking. Only chain / signature / validity are verified. */
    NONE,
    /** OCSP only; fail (REVOCATION_UNKNOWN) if the responder is unreachable. */
    OCSP,
    /** CRL only, with HTTP auto-fetch from each cert's CRL Distribution Points. */
    CRL,
    /** OCSP preferred, CRL used as fallback on OCSP unavailability. */
    OCSP_WITH_CRL_FALLBACK
}
