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
package io.github.kaplaukhd.easypki.tls;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.IPAddress;

/** RFC 9525 DNS-ID and IP-ID matching without DNS resolution or CN fallback. */
final class TlsServerNames {
    private TlsServerNames() {}

    static void requireMatch(X509Certificate certificate, String reference) throws CertificateException {
        if (reference == null || reference.isEmpty() || !ascii(reference)) {
            throw new CertificateException("TLS requires an explicit ASCII DNS or IP reference name; use DNS A-labels");
        }
        String host = reference;
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
            if (!IPAddress.isValidIPv6(host)) throw new CertificateException("Brackets require an IPv6 reference address");
        }
        byte[] address = address(host);
        String dns = address == null ? dnsName(host, false) : null;
        if (address == null && dns == null) throw new CertificateException("Invalid TLS reference name");
        try {
            byte[] outer = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());
            if (outer == null) throw new CertificateException("TLS server certificate has no subjectAltName");
            ASN1Primitive wrapper = ASN1Primitive.fromByteArray(outer);
            if (!(wrapper instanceof ASN1OctetString octets)) throw new CertificateException("Invalid TLS subjectAltName wrapper");
            byte[] encoded = octets.getOctets();
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(encoded);
            if (!(parsed instanceof ASN1Sequence)) throw new CertificateException("Invalid TLS subjectAltName sequence");
            GeneralNames names = GeneralNames.getInstance(parsed);
            if (!Arrays.equals(encoded, names.getEncoded(ASN1Encoding.DER))) {
                throw new CertificateException("TLS subjectAltName does not use canonical DER");
            }
            for (GeneralName name : names.getNames()) {
                if (address != null && name.getTagNo() == GeneralName.iPAddress) {
                    byte[] presented = ASN1OctetString.getInstance(name.getName()).getOctets();
                    if ((presented.length == 4 || presented.length == 16) && Arrays.equals(address, presented)) return;
                } else if (dns != null && name.getTagNo() == GeneralName.dNSName) {
                    String presented = dnsName(ASN1IA5String.getInstance(name.getName()).getString(), true);
                    if (presented == null) continue;
                    if (presented.equals(dns)) return;
                    if (presented.startsWith("*.")) {
                        int firstDot = dns.indexOf('.');
                        if (firstDot > 0 && dns.substring(firstDot + 1).equals(presented.substring(2))) return;
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            throw new CertificateException("Invalid TLS subjectAltName", e);
        }
        throw new CertificateException("TLS server subjectAltName does not match the reference name");
    }

    private static byte[] address(String host) throws CertificateException {
        if (IPAddress.isValidIPv4(host)) {
            for (String part : host.split("\\.")) {
                if (part.length() > 1 && part.charAt(0) == '0') {
                    throw new CertificateException("IPv4 reference addresses must not contain leading zeroes");
                }
            }
        } else if (!IPAddress.isValidIPv6(host)) {
            if (host.indexOf(':') >= 0 || host.indexOf('%') >= 0 || host.indexOf('/') >= 0
                    || host.chars().allMatch(character -> character == '.' || character >= '0' && character <= '9')) {
                throw new CertificateException("Invalid TLS IP reference address");
            }
            return null;
        }
        try {
            return ASN1OctetString.getInstance(new GeneralName(GeneralName.iPAddress, host).getName()).getOctets();
        } catch (RuntimeException e) {
            throw new CertificateException("Invalid TLS IP reference address", e);
        }
    }

    private static String dnsName(String value, boolean allowWildcard) {
        if (!ascii(value)) return null;
        // A final DNS root label has no effect on the reference identity.
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.isEmpty() || value.length() > 253) return null;
        String[] labels = value.split("\\.", -1);
        for (int index = 0; index < labels.length; index++) {
            String label = labels[index];
            if (allowWildcard && index == 0 && label.equals("*") && labels.length > 1) continue;
            if (label.isEmpty() || label.length() > 63 || !letterOrDigit(label.charAt(0))
                    || !letterOrDigit(label.charAt(label.length() - 1))) return null;
            for (int position = 0; position < label.length(); position++) {
                char character = label.charAt(position);
                if (!letterOrDigit(character) && character != '-') return null;
            }
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static boolean ascii(String value) {
        for (int index = 0; index < value.length(); index++) if (value.charAt(index) > 0x7f) return false;
        return true;
    }

    private static boolean letterOrDigit(char value) {
        return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9';
    }
}
