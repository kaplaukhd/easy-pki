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

import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Fluent builder for X.500 Distinguished Names.
 *
 * <p>Call order is preserved: attributes appear in the resulting DN in the
 * order they were added, which is the RFC 4514 convention (most-specific
 * first, e.g. {@code CN=host, O=Corp, C=RU}).
 *
 * <p>Typical use through a certificate builder:
 * <pre>{@code
 * PkiCertificate.selfSigned()
 *     .subject(dn -> dn.cn("example.com").o("Corp").c("RU"))
 *     // ...
 * }</pre>
 */
public final class DnBuilder {

    private final X500NameBuilder delegate = new X500NameBuilder(BCStyle.INSTANCE);

    DnBuilder() {
        // Package-private: instances are obtained through certificate builders.
    }

    /** Adds {@code CN} (Common Name). */
    public DnBuilder cn(String value) {
        return add(BCStyle.CN, value);
    }

    /** Adds {@code O} (Organisation). */
    public DnBuilder o(String value) {
        return add(BCStyle.O, value);
    }

    /** Adds {@code OU} (Organisational Unit). */
    public DnBuilder ou(String value) {
        return add(BCStyle.OU, value);
    }

    /** Adds {@code C} (Country — two-letter ISO code, e.g. {@code "US"}). */
    public DnBuilder c(String value) {
        return add(BCStyle.C, value);
    }

    /** Adds {@code L} (Locality — city). */
    public DnBuilder l(String value) {
        return add(BCStyle.L, value);
    }

    /** Adds {@code ST} (State or Province). */
    public DnBuilder st(String value) {
        return add(BCStyle.ST, value);
    }

    /** Adds {@code STREET} (Street Address). */
    public DnBuilder street(String value) {
        return add(BCStyle.STREET, value);
    }

    /** Adds {@code emailAddress}. */
    public DnBuilder email(String value) {
        return add(BCStyle.E, value);
    }

    /** Adds {@code SERIALNUMBER} (subject serial number, not the certificate serial). */
    public DnBuilder serialNumber(String value) {
        return add(BCStyle.SERIALNUMBER, value);
    }

    /**
     * Adds an arbitrary attribute by its ASN.1 OID.
     *
     * <p>Prefer the named helpers above when the attribute is standard. This
     * method is useful for non-standard attributes (e.g. corporate or country-
     * specific OIDs).
     *
     * @param oid   the attribute OID in dotted notation, e.g. {@code "2.5.4.3"}.
     * @param value the attribute value.
     */
    public DnBuilder attribute(String oid, String value) {
        Objects.requireNonNull(oid, "oid");
        return add(new ASN1ObjectIdentifier(oid), value);
    }

    private DnBuilder add(ASN1ObjectIdentifier attrOid, String value) {
        Objects.requireNonNull(value, "value");
        delegate.addRDN(attrOid, value);
        return this;
    }

    X500Name toX500Name() {
        return delegate.build();
    }
}
