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

import java.math.BigInteger;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/** Decodes requested extensions without copying requester-supplied authority into a certificate. */
final class CsrPolicySupport {
    private static final Set<String> SHA2 = Set.of("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3");

    private CsrPolicySupport() {}

    record Approved(Integer pathLength, Set<KeyUsage> usages, List<SubjectAlternativeName> names) {}

    static Approved approve(CsrRequest request, CsrIssuancePolicy policy) {
        requireModernCrypto(request);
        if (!request.getAttributes().isEmpty()) throw denied("Unsupported CSR attributes");
        boolean ca = policy.profile() == CertificateProfile.INTERMEDIATE_CA;
        Integer path = ca ? policy.maximumPathLength() : null;
        EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
        List<SubjectAlternativeName> names = List.of();
        for (CsrExtension extension : request.getRequestedExtensions()) {
            ASN1Primitive value = CsrRequest.requireDer(extension.getValue());
            switch (extension.getOid()) {
                case "2.5.29.19" -> path = basicConstraints(value, ca, path);
                case "2.5.29.15" -> usages = keyUsage(value, policy.profile());
                case "2.5.29.37" -> extendedKeyUsage(value, policy.profile());
                case "2.5.29.17" -> names = subjectAlternativeNames(value, policy.profile());
                default -> throw denied("Unsupported requested extension: " + extension.getOid());
            }
        }
        policy.authorize(request, names);
        return new Approved(path, Set.copyOf(usages), List.copyOf(names));
    }

    private static Integer basicConstraints(ASN1Primitive value, boolean caProfile, Integer maximum) {
        if (!(value instanceof ASN1Sequence sequence) || sequence.size() > 2) throw denied("Invalid requested BasicConstraints");
        int index = 0;
        boolean ca = false;
        if (sequence.size() > 0 && sequence.getObjectAt(0) instanceof ASN1Boolean flag) {
            ca = flag.isTrue();
            if (!ca) throw denied("DER BasicConstraints must omit the default CA=false field");
            index++;
        }
        BigInteger path = null;
        if (index < sequence.size() && sequence.getObjectAt(index) instanceof ASN1Integer integer) {
            path = integer.getValue();
            index++;
        }
        if (index != sequence.size() || (path != null && (!ca || path.signum() < 0))) {
            throw denied("Invalid requested BasicConstraints fields");
        }
        if (ca != caProfile) throw denied("Requested CA authority conflicts with certificate profile");
        if (!caProfile) return null;
        if (path == null) return maximum;
        if (path.compareTo(BigInteger.valueOf(maximum)) > 0) throw denied("Requested CA path length exceeds policy");
        return path.intValueExact();
    }

    private static EnumSet<KeyUsage> keyUsage(ASN1Primitive value, CertificateProfile profile) {
        if (!(value instanceof ASN1BitString bits)) throw denied("Requested KeyUsage must be a BIT STRING");
        byte[] bytes = bits.getBytes();
        boolean any = false;
        for (int index = 0; index < bytes.length * 8L - bits.getPadBits(); index++) {
            if ((bytes[index / 8] & (0x80 >>> (index % 8))) != 0) {
                any = true;
                if (index > 8) throw denied("Unknown requested KeyUsage bit");
            }
        }
        if (!any) throw denied("Requested KeyUsage must not be empty");
        org.bouncycastle.asn1.x509.KeyUsage requested = org.bouncycastle.asn1.x509.KeyUsage.getInstance(bits);
        EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
        for (KeyUsage usage : KeyUsage.values()) if (requested.hasUsages(usage.bcBit())) usages.add(usage);
        int mask = 0;
        for (KeyUsage usage : usages) mask |= usage.bcBit();
        requireSameEncoding(value, new org.bouncycastle.asn1.x509.KeyUsage(mask));
        Set<KeyUsage> permitted = switch (profile) {
            case INTERMEDIATE_CA -> EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
            case TLS_SERVER -> EnumSet.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT);
            case TLS_CLIENT -> EnumSet.of(KeyUsage.DIGITAL_SIGNATURE);
            default -> throw denied("Unsupported CSR issuance profile");
        };
        if (!permitted.containsAll(usages)) throw denied("Requested KeyUsage conflicts with certificate profile");
        return usages;
    }

    private static void extendedKeyUsage(ASN1Primitive value, CertificateProfile profile) {
        if (!(value instanceof ASN1Sequence sequence) || sequence.size() == 0) throw denied("Requested ExtendedKeyUsage must not be empty");
        String permitted = switch (profile) {
            case TLS_SERVER -> "1.3.6.1.5.5.7.3.1";
            case TLS_CLIENT -> "1.3.6.1.5.5.7.3.2";
            default -> throw denied("CA profile does not permit ExtendedKeyUsage");
        };
        Set<String> seen = new HashSet<>();
        for (ASN1Encodable entry : sequence) {
            if (!(entry instanceof ASN1ObjectIdentifier oid) || !permitted.equals(oid.getId()) || !seen.add(oid.getId())) {
                throw denied("Requested ExtendedKeyUsage conflicts with certificate profile");
            }
        }
    }

    private static List<SubjectAlternativeName> subjectAlternativeNames(ASN1Primitive value, CertificateProfile profile) {
        if (!(value instanceof ASN1Sequence sequence) || sequence.size() == 0) throw denied("Requested SAN must not be empty");
        GeneralNames generalNames = GeneralNames.getInstance(sequence);
        requireSameEncoding(value, generalNames);
        if (profile == CertificateProfile.TLS_SERVER) TlsProfileNames.validateServer(generalNames);
        else TlsProfileNames.validateClient(generalNames);
        List<SubjectAlternativeName> names = new ArrayList<>();
        for (GeneralName name : generalNames.getNames()) {
            String text;
            if (name.getTagNo() == GeneralName.iPAddress) {
                try {
                    byte[] address = ASN1OctetString.getInstance(name.getName()).getOctets();
                    // InetAddress collapses mapped IPv6 into IPv4; preserve the CSR's address family.
                    text = (address.length == 16 ? Inet6Address.getByAddress(null, address, -1)
                            : InetAddress.getByAddress(address)).getHostAddress();
                } catch (UnknownHostException e) {
                    throw new IllegalArgumentException("Invalid requested IP SAN", e);
                }
            } else {
                text = ASN1IA5String.getInstance(name.getName()).getString();
            }
            names.add(new SubjectAlternativeName(SubjectAlternativeName.fromJcaTypeCode(name.getTagNo()), text));
        }
        return names;
    }

    private static void requireModernCrypto(CsrRequest request) {
        PublicKey key = request.getPublicKey();
        boolean allowed = key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= 2048
                || key instanceof ECPublicKey ec && ec.getParams() != null
                    && ec.getParams().getCurve().getField().getFieldSize() >= 256
                    && ec.getParams().getOrder().bitLength() >= 256
                || "1.3.101.112".equals(SubjectPublicKeyInfo.getInstance(key.getEncoded())
                    .getAlgorithm().getAlgorithm().getId());
        if (!allowed) throw denied("CSR public key does not meet CA policy minimums");
        ASN1Sequence encoded = ASN1Sequence.getInstance(CsrRequest.requireDer(request.toDer()));
        AlgorithmIdentifier algorithm = CsrRequest.algorithmIdentifier(encoded.getObjectAt(1));
        boolean modern = switch (algorithm.getAlgorithm().getId()) {
            case "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
                 "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4", "1.3.101.112" -> true;
            case "1.2.840.113549.1.1.10" -> {
                // Proof verification has already validated the complete PSS parameter schema.
                RSASSAPSSparams pss = RSASSAPSSparams.getInstance(algorithm.getParameters());
                AlgorithmIdentifier mgfDigest = AlgorithmIdentifier.getInstance(pss.getMaskGenAlgorithm().getParameters());
                yield SHA2.contains(pss.getHashAlgorithm().getAlgorithm().getId()) && SHA2.contains(mgfDigest.getAlgorithm().getId());
            }
            default -> false;
        };
        if (!modern) throw denied("CSR signature algorithm does not meet CA policy minimums");
    }

    private static IllegalArgumentException denied(String message) { return new IllegalArgumentException(message); }

    private static void requireSameEncoding(ASN1Primitive original, ASN1Encodable normalized) {
        try {
            if (!Arrays.equals(original.getEncoded(ASN1Encoding.DER), normalized.toASN1Primitive().getEncoded(ASN1Encoding.DER))) {
                throw denied("Requested extension does not use canonical DER for its schema");
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid requested extension encoding", e);
        }
    }
}
