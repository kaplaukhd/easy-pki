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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.IPAddress;

/**
 * Bounded SAN syntax checks for the opt-in TLS profiles. No DNS resolution or
 * ownership, public-suffix, URI-scheme, or mailbox-deliverability checks occur.
 *
 * <p>DNS names use ASCII letters, digits, and hyphens, with labels of 1–63
 * characters and at most 253 characters overall. Single-label private names
 * are allowed; trailing dots are not. A wildcard must be the entire leftmost
 * label and have at least two following labels. Internationalized names must
 * be supplied as ASCII A-labels before ASN.1 encoding.
 *
 * <p>Client email identities use the conservative ASCII dot-atom local-part
 * form, followed by an ordinary DNS domain. Quoted local parts, comments,
 * display names, address literals, and internationalized mailboxes are not
 * accepted. URI identities must be absolute ASCII URIs with a nonempty
 * scheme-specific part; application-specific URI semantics are not checked.
 *
 * <p>These checks operate on encoded names. Callers must reject non-ASCII
 * input before constructing IA5String values, which can otherwise lose data.
 */
final class TlsProfileNames {

    private static final Pattern EMAIL_LOCAL_PART = Pattern.compile(
            "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*");

    private TlsProfileNames() {
    }

    static boolean hasNames(GeneralNames names) {
        return names != null && names.getNames().length != 0;
    }

    static void validateServer(GeneralNames names) {
        if (!hasNames(names)) {
            throw new IllegalArgumentException("TLS server profile requires at least one DNS or IP SAN");
        }
        validate(names, false);
    }

    static void validateClient(GeneralNames names) {
        if (hasNames(names)) {
            validate(names, true);
        }
    }

    private static void validate(GeneralNames names, boolean client) {
        for (GeneralName name : names.getNames()) {
            if (name == null) {
                throw new IllegalArgumentException("TLS profile SAN entries must not be null");
            }
            switch (name.getTagNo()) {
                case GeneralName.dNSName -> validateDns(text(name), true);
                case GeneralName.iPAddress -> validateIp(name);
                case GeneralName.rfc822Name -> {
                    if (!client) {
                        throw unsupported(name);
                    }
                    validateEmail(text(name));
                }
                case GeneralName.uniformResourceIdentifier -> {
                    if (!client) {
                        throw unsupported(name);
                    }
                    validateUri(text(name));
                }
                default -> throw unsupported(name);
            }
        }
    }

    private static IllegalArgumentException unsupported(GeneralName name) {
        return new IllegalArgumentException("Unsupported SAN type for TLS profile: " + name.getTagNo());
    }

    private static String text(GeneralName name) {
        if (name.getName() == null
                || !(name.getName().toASN1Primitive() instanceof ASN1IA5String value)) {
            throw new IllegalArgumentException("TLS profile textual SAN must be an IA5String");
        }
        String text = value.getString();
        if (text.isEmpty() || !ASN1IA5String.isIA5String(text)) {
            throw new IllegalArgumentException("TLS profile SAN must be nonempty ASCII; use ASCII A-labels for DNS names");
        }
        return text;
    }

    private static void validateDns(String value, boolean allowWildcard) {
        if (value.length() > 253) {
            throw new IllegalArgumentException("DNS SAN must contain at most 253 characters");
        }
        String domain = value;
        if (allowWildcard && value.startsWith("*.")) {
            domain = value.substring(2);
            if (domain.indexOf('.') < 0) {
                throw new IllegalArgumentException("DNS SAN wildcard requires at least two following labels");
            }
        }
        if (IPAddress.isValid(domain)) {
            throw new IllegalArgumentException("IP literals must use an IP SAN, not a DNS SAN");
        }
        for (String label : domain.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63
                    || !isLetterOrDigit(label.charAt(0))
                    || !isLetterOrDigit(label.charAt(label.length() - 1))) {
                throw new IllegalArgumentException("DNS SAN labels must contain 1–63 ASCII letters, digits, or hyphens"
                        + " and must start and end with a letter or digit");
            }
            for (int i = 0; i < label.length(); i++) {
                char character = label.charAt(i);
                if (!isLetterOrDigit(character) && character != '-') {
                    throw new IllegalArgumentException("DNS SAN contains an invalid character or wildcard");
                }
            }
        }
    }

    private static boolean isLetterOrDigit(char character) {
        return character >= 'a' && character <= 'z'
                || character >= 'A' && character <= 'Z'
                || character >= '0' && character <= '9';
    }

    private static void validateIp(GeneralName name) {
        if (name.getName() == null
                || !(name.getName().toASN1Primitive() instanceof ASN1OctetString address)
                || (address.getOctets().length != 4 && address.getOctets().length != 16)) {
            throw new IllegalArgumentException("IP SAN must contain exactly 4 or 16 address octets; masks are not allowed");
        }
    }

    private static void validateEmail(String value) {
        int separator = value.indexOf('@');
        if (separator <= 0 || separator > 64 || separator != value.lastIndexOf('@')
                || separator == value.length() - 1 || value.length() > 254
                || !EMAIL_LOCAL_PART.matcher(value.substring(0, separator)).matches()) {
            throw new IllegalArgumentException("Email SAN must be an ASCII dot-atom mailbox with a DNS domain");
        }
        validateDns(value.substring(separator + 1), false);
    }

    private static void validateUri(String value) {
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || uri.getRawSchemeSpecificPart() == null
                    || uri.getRawSchemeSpecificPart().isEmpty()) {
                throw new IllegalArgumentException("URI SAN must be absolute with a nonempty scheme-specific part");
            }
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("URI SAN must be a syntactically valid absolute ASCII URI", exception);
        }
    }
}
