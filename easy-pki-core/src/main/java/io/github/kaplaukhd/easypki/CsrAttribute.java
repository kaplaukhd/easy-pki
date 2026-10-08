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

import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Immutable PKCS#10 attribute available for inspection. Each value is a complete
 * DER-encoded ASN.1 value; interpretation and authorization remain caller policy.
 */
public final class CsrAttribute {
    private final String oid;
    private final List<byte[]> values;

    /** Creates an attribute with at least one DER-encoded value, copying all input. */
    public CsrAttribute(String oid, List<byte[]> values) {
        this.oid = new ASN1ObjectIdentifier(Objects.requireNonNull(oid, "oid")).getId();
        Objects.requireNonNull(values, "values");
        if (values.isEmpty()) throw new IllegalArgumentException("CSR attribute must contain a value");
        this.values = values.stream().map(value -> {
            byte[] copy = Objects.requireNonNull(value, "attribute value").clone();
            CsrRequest.requireDer(copy);
            return copy;
        }).toList();
    }

    /** Returns the dotted-decimal attribute OID. */
    public String getOid() { return oid; }

    /** Returns an unmodifiable list of fresh defensive copies of the attribute values. */
    public List<byte[]> getValues() { return values.stream().map(byte[]::clone).toList(); }
}
