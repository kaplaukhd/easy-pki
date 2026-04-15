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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * Read-only view over an {@link X509Certificate}. Provides ergonomic accessors
 * for the information developers usually want — validity, SANs, extensions,
 * fingerprints — without wrestling with the low-level JCA API.
 *
 * <pre>{@code
 * PkiCertInfo info = PkiCertInfo.of(cert);
 *
 * info.getSubject();                          // "CN=api.example.com, O=Corp"
 * info.isExpired();                           // false
 * info.isExpiringWithin(Duration.ofDays(30)); // monitoring hook
 * info.getSans();                             // List<SubjectAlternativeName>
 * info.getFingerprint(HashAlgorithm.SHA256);  // "AB:CD:..."
 * }</pre>
 */
public final class PkiCertInfo {

    private final X509Certificate certificate;

    private PkiCertInfo(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /** Wraps the given certificate in an inspection view. */
    public static PkiCertInfo of(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        return new PkiCertInfo(certificate);
    }

    /** Returns the underlying certificate. */
    public X509Certificate getCertificate() {
        return certificate;
    }

    // ---------- Subject / issuer / serial ----------

    /** RFC 2253 / 4514 subject distinguished name. */
    public String getSubject() {
        return certificate.getSubjectX500Principal().getName();
    }

    /** RFC 2253 / 4514 issuer distinguished name. */
    public String getIssuer() {
        return certificate.getIssuerX500Principal().getName();
    }

    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }

    /** Returns whether the certificate is self-signed (subject DN equals issuer DN). */
    public boolean isSelfSigned() {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    // ---------- Validity ----------

    public Instant getNotBefore() {
        return certificate.getNotBefore().toInstant();
    }

    public Instant getNotAfter() {
        return certificate.getNotAfter().toInstant();
    }

    /** {@code true} if the certificate's {@code notAfter} is already in the past. */
    public boolean isExpired() {
        return Instant.now().isAfter(getNotAfter());
    }

    /** {@code true} if the certificate is not yet valid ({@code notBefore} in the future). */
    public boolean isNotYetValid() {
        return Instant.now().isBefore(getNotBefore());
    }

    /**
     * {@code true} if the certificate is either already expired or will expire
     * within the given duration from now. Useful for monitoring.
     */
    public boolean isExpiringWithin(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        return Instant.now().plus(duration).isAfter(getNotAfter());
    }

    // ---------- Basic constraints ----------

    /** {@code true} if the certificate is a CA (BasicConstraints {@code cA=TRUE}). */
    public boolean isCA() {
        return certificate.getBasicConstraints() != -1;
    }

    /**
     * Maximum number of non-self-issued intermediate CAs that may follow this
     * certificate in a valid chain. {@code null} if the certificate is not a CA
     * or the constraint is unlimited.
     */
    public Integer getPathLength() {
        int bc = certificate.getBasicConstraints();
        if (bc == -1 || bc == Integer.MAX_VALUE) {
            return null;
        }
        return bc;
    }

    // ---------- Key usage ----------

    public Set<KeyUsage> getKeyUsages() {
        boolean[] bits = certificate.getKeyUsage();
        if (bits == null) {
            return Collections.emptySet();
        }
        EnumSet<KeyUsage> out = EnumSet.noneOf(KeyUsage.class);
        KeyUsage[] all = KeyUsage.values(); // declared order matches X.509 bit order
        for (int i = 0; i < bits.length && i < all.length; i++) {
            if (bits[i]) {
                out.add(all[i]);
            }
        }
        return out;
    }

    public Set<ExtendedKeyUsage> getExtendedKeyUsages() {
        List<String> oids;
        try {
            oids = certificate.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            throw new IllegalStateException("Malformed ExtendedKeyUsage extension", e);
        }
        if (oids == null) {
            return Collections.emptySet();
        }
        EnumSet<ExtendedKeyUsage> out = EnumSet.noneOf(ExtendedKeyUsage.class);
        for (String oid : oids) {
            for (ExtendedKeyUsage eku : ExtendedKeyUsage.values()) {
                if (eku.purposeId().getId().equals(oid)) {
                    out.add(eku);
                    break;
                }
            }
        }
        return out;
    }

    /** Returns the raw OIDs from the ExtendedKeyUsage extension, preserving unrecognised ones. */
    public List<String> getExtendedKeyUsageOids() {
        try {
            List<String> oids = certificate.getExtendedKeyUsage();
            return oids == null ? Collections.emptyList() : List.copyOf(oids);
        } catch (CertificateParsingException e) {
            throw new IllegalStateException("Malformed ExtendedKeyUsage extension", e);
        }
    }

    // ---------- SAN ----------

    public List<SubjectAlternativeName> getSans() {
        Collection<List<?>> raw;
        try {
            raw = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new IllegalStateException("Malformed SubjectAlternativeName extension", e);
        }
        if (raw == null) {
            return Collections.emptyList();
        }
        List<SubjectAlternativeName> out = new ArrayList<>(raw.size());
        for (List<?> entry : raw) {
            int code = (Integer) entry.get(0);
            Object value = entry.get(1);
            out.add(new SubjectAlternativeName(
                    SubjectAlternativeName.fromJcaTypeCode(code),
                    String.valueOf(value)));
        }
        return out;
    }

    // ---------- AIA / CDP ----------

    /** OCSP responder URLs from the Authority Information Access extension. */
    public List<String> getOcspUrls() {
        byte[] ext = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ext == null) {
            return Collections.emptyList();
        }
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
                ASN1OctetString.getInstance(ext).getOctets());
        List<String> out = new ArrayList<>();
        for (AccessDescription desc : aia.getAccessDescriptions()) {
            if (AccessDescription.id_ad_ocsp.equals(desc.getAccessMethod())) {
                GeneralName location = desc.getAccessLocation();
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    out.add(location.getName().toString());
                }
            }
        }
        return out;
    }

    /** CRL Distribution Point URIs. */
    public List<String> getCrlUrls() {
        byte[] ext = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return Collections.emptyList();
        }
        CRLDistPoint cdp = CRLDistPoint.getInstance(ASN1OctetString.getInstance(ext).getOctets());
        List<String> out = new ArrayList<>();
        for (DistributionPoint dp : cdp.getDistributionPoints()) {
            DistributionPointName name = dp.getDistributionPoint();
            if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                continue;
            }
            GeneralNames names = (GeneralNames) name.getName();
            for (GeneralName gn : names.getNames()) {
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    out.add(gn.getName().toString());
                }
            }
        }
        return out;
    }

    // ---------- Public key ----------

    /** {@code "RSA"}, {@code "EC"}, etc. */
    public String getPublicKeyAlgorithm() {
        return certificate.getPublicKey().getAlgorithm();
    }

    /**
     * Size of the public key in bits (modulus length for RSA, field size for EC).
     * Returns {@code -1} for unsupported key algorithms.
     */
    public int getPublicKeySize() {
        java.security.PublicKey key = certificate.getPublicKey();
        if (key instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (key instanceof ECPublicKey ec) {
            return ec.getParams().getOrder().bitLength();
        }
        return -1;
    }

    // ---------- Fingerprint ----------

    /**
     * Returns the colon-separated uppercase hexadecimal fingerprint of the
     * DER-encoded certificate (e.g. {@code "AB:CD:EF:..."}).
     */
    public String getFingerprint(HashAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.jcaName());
            byte[] digest = md.digest(certificate.getEncoded());
            return hexColon(digest);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to compute fingerprint", e);
        }
    }

    private static String hexColon(byte[] bytes) {
        String hex = HexFormat.of().withUpperCase().formatHex(bytes);
        StringBuilder sb = new StringBuilder(hex.length() + hex.length() / 2);
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(hex, i, i + 2);
        }
        return sb.toString();
    }

    // ---------- Raw OID constants (for convenience) ----------

    /** Returns whether the certificate declares the given extended-key-usage OID. */
    public boolean hasExtendedKeyUsage(String oid) {
        Objects.requireNonNull(oid, "oid");
        return getExtendedKeyUsageOids().contains(oid);
    }

    /** Returns whether the certificate declares the given purpose. */
    public boolean hasExtendedKeyUsage(ExtendedKeyUsage purpose) {
        Objects.requireNonNull(purpose, "purpose");
        return hasExtendedKeyUsage(purpose.purposeId().getId());
    }

    static String oidOf(KeyPurposeId id) {
        return id.getId();
    }
}
