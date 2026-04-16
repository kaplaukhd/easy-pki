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
 * Reasons a certificate may be revoked (RFC 5280 §5.3.1 {@code CRLReason}).
 */
public enum RevocationReason {

    /** No specific reason given — the default. */
    UNSPECIFIED(0),

    /** The private key was compromised. */
    KEY_COMPROMISE(1),

    /** The issuing CA's private key was compromised. */
    CA_COMPROMISE(2),

    /** The subject's affiliation (e.g. organisation) has changed. */
    AFFILIATION_CHANGED(3),

    /** The certificate has been superseded by a new issuance. */
    SUPERSEDED(4),

    /** The subject ceased to operate. */
    CESSATION_OF_OPERATION(5),

    /** Temporary revocation — may be lifted later. */
    CERTIFICATE_HOLD(6),

    /** Previously-held certificate is no longer on hold (delta CRL use). */
    REMOVE_FROM_CRL(8),

    /** Privileges granted by the certificate have been withdrawn. */
    PRIVILEGE_WITHDRAWN(9),

    /** An attribute-authority key was compromised. */
    AA_COMPROMISE(10);

    private final int crlReasonCode;

    RevocationReason(int crlReasonCode) {
        this.crlReasonCode = crlReasonCode;
    }

    /** Returns the numeric CRLReason code from RFC 5280. */
    public int crlReasonCode() {
        return crlReasonCode;
    }

    /** Maps a CRLReason code back to this enum, returning {@link #UNSPECIFIED} if unknown. */
    public static RevocationReason fromCode(int code) {
        for (RevocationReason r : values()) {
            if (r.crlReasonCode == code) {
                return r;
            }
        }
        return UNSPECIFIED;
    }
}
