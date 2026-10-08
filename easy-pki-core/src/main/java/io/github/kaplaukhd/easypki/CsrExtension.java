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

/**
 * Immutable requested X.509 extension, preserving its OID, critical flag and
 * opaque extension value. A requested extension is not an authorization to issue it.
 */
public final class CsrExtension {
    private final String oid;
    private final boolean critical;
    private final byte[] value;

    /**
     * Creates an extension value. {@code value} is the inner extension encoding,
     * without the outer OCTET STRING, and is copied defensively. Extension-specific
     * syntax and policy are checked by the issuer rather than by this value object.
     */
    public CsrExtension(String oid, boolean critical, byte[] value) {
        this.oid = new ASN1ObjectIdentifier(Objects.requireNonNull(oid, "oid")).getId();
        this.critical = critical;
        this.value = Objects.requireNonNull(value, "value").clone();
    }

    /** Returns the dotted-decimal extension OID. */
    public String getOid() { return oid; }

    /** Returns whether the request marks this extension critical. */
    public boolean isCritical() { return critical; }

    /** Returns a defensive copy of the inner extension encoding. */
    public byte[] getValue() { return value.clone(); }
}
