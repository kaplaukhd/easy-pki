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

import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * Purposes of the X.509 {@code ExtendedKeyUsage} extension (RFC 5280 §4.2.1.12).
 *
 * <p>Add to a certificate builder via {@code extendedKeyUsage(...)} to restrict
 * what the public key may be used for beyond the basic {@link KeyUsage} bits.
 */
public enum ExtendedKeyUsage {

    /** TLS Web Server Authentication ({@code 1.3.6.1.5.5.7.3.1}). */
    TLS_SERVER(KeyPurposeId.id_kp_serverAuth),

    /** TLS Web Client Authentication ({@code 1.3.6.1.5.5.7.3.2}). */
    TLS_CLIENT(KeyPurposeId.id_kp_clientAuth),

    /** Code Signing ({@code 1.3.6.1.5.5.7.3.3}). */
    CODE_SIGNING(KeyPurposeId.id_kp_codeSigning),

    /** E-mail Protection — S/MIME ({@code 1.3.6.1.5.5.7.3.4}). */
    EMAIL_PROTECTION(KeyPurposeId.id_kp_emailProtection),

    /** Time Stamping ({@code 1.3.6.1.5.5.7.3.8}). */
    TIME_STAMPING(KeyPurposeId.id_kp_timeStamping),

    /** OCSP response signing ({@code 1.3.6.1.5.5.7.3.9}). */
    OCSP_SIGNING(KeyPurposeId.id_kp_OCSPSigning);

    private final KeyPurposeId purposeId;

    ExtendedKeyUsage(KeyPurposeId purposeId) {
        this.purposeId = purposeId;
    }

    KeyPurposeId purposeId() {
        return purposeId;
    }
}
