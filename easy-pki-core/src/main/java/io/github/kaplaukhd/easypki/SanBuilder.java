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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Fluent builder for the {@code SubjectAlternativeName} (SAN) extension.
 *
 * <p>Typical use through a certificate builder:
 * <pre>{@code
 * PkiCertificate.signed()
 *     .san(s -> s.dns("api.example.com")
 *                .dns("*.api.example.com")
 *                .ip("10.0.0.1"))
 *     // ...
 * }</pre>
 */
public final class SanBuilder {

    private final List<GeneralName> names = new ArrayList<>();

    SanBuilder() {
        // Package-private: obtained through certificate builders.
    }

    /** Adds a {@code dNSName} entry — typically a hostname or wildcard. */
    public SanBuilder dns(String hostname) {
        Objects.requireNonNull(hostname, "hostname");
        names.add(new GeneralName(GeneralName.dNSName, hostname));
        return this;
    }

    /** Adds an {@code iPAddress} entry (IPv4 or IPv6 literal, e.g. {@code "10.0.0.1"}). */
    public SanBuilder ip(String ipAddress) {
        Objects.requireNonNull(ipAddress, "ipAddress");
        names.add(new GeneralName(GeneralName.iPAddress, ipAddress));
        return this;
    }

    /** Adds an {@code rfc822Name} entry — an e-mail address. */
    public SanBuilder email(String emailAddress) {
        Objects.requireNonNull(emailAddress, "emailAddress");
        names.add(new GeneralName(GeneralName.rfc822Name, emailAddress));
        return this;
    }

    /** Adds a {@code uniformResourceIdentifier} entry — a URI. */
    public SanBuilder uri(String uri) {
        Objects.requireNonNull(uri, "uri");
        names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
        return this;
    }

    boolean isEmpty() {
        return names.isEmpty();
    }

    GeneralName[] toGeneralNames() {
        return names.toArray(new GeneralName[0]);
    }
}
