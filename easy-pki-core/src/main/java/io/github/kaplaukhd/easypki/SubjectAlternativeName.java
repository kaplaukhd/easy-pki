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
 * A single Subject Alternative Name entry, as returned by
 * {@link PkiCertInfo#getSans()}.
 *
 * @param type  the SAN type (one of {@link Type})
 * @param value the string value (e.g. the DNS name, IP literal, e-mail, URI)
 */
public record SubjectAlternativeName(Type type, String value) {

    /** SAN entry types commonly encountered in X.509 certificates. */
    public enum Type {
        /** DNS name (RFC 5280 type {@code 2}). */
        DNS,
        /** IPv4 or IPv6 literal (RFC 5280 type {@code 7}). */
        IP_ADDRESS,
        /** RFC 822 e-mail address (RFC 5280 type {@code 1}). */
        EMAIL,
        /** URI (RFC 5280 type {@code 6}). */
        URI,
        /** Directory name (RFC 5280 type {@code 4}). */
        DIRECTORY_NAME,
        /** Any other SAN type. */
        OTHER
    }

    static Type fromJcaTypeCode(int code) {
        return switch (code) {
            case 1 -> Type.EMAIL;
            case 2 -> Type.DNS;
            case 4 -> Type.DIRECTORY_NAME;
            case 6 -> Type.URI;
            case 7 -> Type.IP_ADDRESS;
            default -> Type.OTHER;
        };
    }
}
