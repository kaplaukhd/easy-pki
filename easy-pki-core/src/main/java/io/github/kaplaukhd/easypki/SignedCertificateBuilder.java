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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Fluent builder for X.509 certificates signed by an issuing CA.
 *
 * <p>Obtain an instance via {@link PkiCertificate#signed()}. The issuer
 * certificate supplies the issuer DN and authority key identifier; the issuer's
 * private key signs the resulting certificate.
 *
 * <pre>{@code
 * X509Certificate leaf = PkiCertificate.signed()
 *     .subject("CN=api.example.com")
 *     .publicKey(serverKeys.getPublic())
 *     .issuer(caCert, caPrivateKey)
 *     .validFor(Duration.ofDays(365))
 *     .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
 *     .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
 *     .san(s -> s.dns("api.example.com").dns("*.api.example.com"))
 *     .crlDistributionPoint("http://crl.example.org/ca.crl")
 *     .ocsp("http://ocsp.example.org")
 *     .build();
 * }</pre>
 *
 * <p>Defaults applied automatically:
 * <ul>
 *   <li>Random 20-byte positive serial number (RFC 5280 §4.1.2.2).</li>
 *   <li>Signature algorithm {@code SHA256withRSA} / {@code SHA256withECDSA}
 *       derived from the <em>issuer's</em> private key.</li>
 *   <li>{@code notBefore} = now (when not explicitly set).</li>
 *   <li>SubjectKeyIdentifier derived from the subject public key;
 *       AuthorityKeyIdentifier derived from the issuer's public key.</li>
 * </ul>
 */
public final class SignedCertificateBuilder {

    private X500Name subject;
    private PublicKey subjectPublicKey;
    private X509Certificate issuerCertificate;
    private PrivateKey issuerPrivateKey;

    private Instant notBefore;
    private Instant notAfter;
    private Duration validFor;

    private BigInteger serialNumber;
    private String signatureAlgorithm;

    private boolean isCA;
    private Integer pathLength;

    private final Set<KeyUsage> keyUsages = EnumSet.noneOf(KeyUsage.class);
    private final Set<ExtendedKeyUsage> extendedKeyUsages = EnumSet.noneOf(ExtendedKeyUsage.class);

    private SanBuilder sanBuilder;
    private final List<String> crlDistributionPoints = new ArrayList<>();
    private final List<String> ocspUrls = new ArrayList<>();

    SignedCertificateBuilder() {
        // Package-private: use PkiCertificate.signed().
    }

    /** Sets the subject distinguished name from an RFC 4514 string. */
    public SignedCertificateBuilder subject(String rfc4514) {
        Objects.requireNonNull(rfc4514, "rfc4514");
        this.subject = new X500Name(rfc4514);
        return this;
    }

    /** Sets the subject distinguished name using a fluent sub-builder. */
    public SignedCertificateBuilder subject(Consumer<DnBuilder> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        DnBuilder dn = new DnBuilder();
        configurer.accept(dn);
        this.subject = dn.toX500Name();
        return this;
    }

    /** Sets the subject's public key (the key being certified). */
    public SignedCertificateBuilder publicKey(PublicKey publicKey) {
        this.subjectPublicKey = Objects.requireNonNull(publicKey, "publicKey");
        return this;
    }

    /**
     * Convenience overload — takes the public key from a {@link KeyPair}.
     * Equivalent to {@code publicKey(keyPair.getPublic())}.
     */
    public SignedCertificateBuilder keyPair(KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair");
        return publicKey(keyPair.getPublic());
    }

    /**
     * Sets the issuing CA — its subject DN becomes the new certificate's issuer,
     * its public key is used to derive the Authority Key Identifier, and its
     * private key signs the new certificate.
     */
    public SignedCertificateBuilder issuer(X509Certificate issuerCertificate,
                                           PrivateKey issuerPrivateKey) {
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        this.issuerPrivateKey = Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey");
        return this;
    }

    /**
     * Sets the validity duration relative to {@link #validFrom(Instant)} (or now).
     * Mutually exclusive with {@link #validUntil(Instant)}.
     */
    public SignedCertificateBuilder validFor(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        if (duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(
                    "validFor duration must be positive, got " + duration);
        }
        this.validFor = duration;
        this.notAfter = null;
        return this;
    }

    /** Sets {@code notBefore} explicitly. Default is now. */
    public SignedCertificateBuilder validFrom(Instant notBefore) {
        this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
        return this;
    }

    /** Sets {@code notAfter} explicitly. Mutually exclusive with {@link #validFor(Duration)}. */
    public SignedCertificateBuilder validUntil(Instant notAfter) {
        this.notAfter = Objects.requireNonNull(notAfter, "notAfter");
        this.validFor = null;
        return this;
    }

    /** Overrides the random default serial number. */
    public SignedCertificateBuilder serialNumber(BigInteger serialNumber) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        if (serialNumber.signum() <= 0) {
            throw new IllegalArgumentException(
                    "serialNumber must be positive, got " + serialNumber);
        }
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * Overrides the JCA signature algorithm name. By default the algorithm is
     * derived from the <em>issuer's</em> private key type.
     */
    public SignedCertificateBuilder signatureAlgorithm(String algorithm) {
        this.signatureAlgorithm = Objects.requireNonNull(algorithm, "algorithm");
        return this;
    }

    /** Marks the certificate as a CA. Default is {@code false}. */
    public SignedCertificateBuilder isCA(boolean ca) {
        this.isCA = ca;
        return this;
    }

    /**
     * Sets the CA path length constraint. Implies {@link #isCA(boolean) isCA(true)}.
     */
    public SignedCertificateBuilder pathLength(int pathLength) {
        if (pathLength < 0) {
            throw new IllegalArgumentException(
                    "pathLength must be >= 0, got " + pathLength);
        }
        this.pathLength = pathLength;
        this.isCA = true;
        return this;
    }

    /** Adds {@code KeyUsage} bits. Multiple calls accumulate. */
    public SignedCertificateBuilder keyUsage(KeyUsage... usages) {
        Objects.requireNonNull(usages, "usages");
        for (KeyUsage usage : usages) {
            keyUsages.add(Objects.requireNonNull(usage, "usage"));
        }
        return this;
    }

    /** Adds {@code ExtendedKeyUsage} purposes. Multiple calls accumulate. */
    public SignedCertificateBuilder extendedKeyUsage(ExtendedKeyUsage... purposes) {
        Objects.requireNonNull(purposes, "purposes");
        for (ExtendedKeyUsage purpose : purposes) {
            extendedKeyUsages.add(Objects.requireNonNull(purpose, "purpose"));
        }
        return this;
    }

    /**
     * Configures the Subject Alternative Name extension. Multiple calls
     * accumulate entries.
     */
    public SignedCertificateBuilder san(Consumer<SanBuilder> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        if (sanBuilder == null) {
            sanBuilder = new SanBuilder();
        }
        configurer.accept(sanBuilder);
        return this;
    }

    /**
     * Adds a URI to the CRL Distribution Points extension. Call more than once
     * to add multiple endpoints.
     */
    public SignedCertificateBuilder crlDistributionPoint(String url) {
        Objects.requireNonNull(url, "url");
        crlDistributionPoints.add(url);
        return this;
    }

    /**
     * Adds an OCSP responder URL to the Authority Information Access extension.
     * Call more than once to add multiple responders.
     */
    public SignedCertificateBuilder ocsp(String url) {
        Objects.requireNonNull(url, "url");
        ocspUrls.add(url);
        return this;
    }

    /**
     * Builds and signs the certificate.
     *
     * @throws IllegalStateException if required fields are missing.
     */
    public X509Certificate build() {
        requireState(subject != null, "subject is required");
        requireState(subjectPublicKey != null, "publicKey (or keyPair) is required");
        requireState(issuerCertificate != null && issuerPrivateKey != null,
                "issuer(certificate, privateKey) is required");
        requireState(validFor != null || notAfter != null,
                "either validFor(Duration) or validUntil(Instant) is required");

        Instant resolvedNotBefore = (notBefore != null) ? notBefore : Instant.now();
        Instant resolvedNotAfter = (notAfter != null)
                ? notAfter
                : resolvedNotBefore.plus(validFor);

        if (!resolvedNotAfter.isAfter(resolvedNotBefore)) {
            throw new IllegalStateException(
                    "notAfter (" + resolvedNotAfter + ") must be after notBefore ("
                            + resolvedNotBefore + ")");
        }

        BigInteger resolvedSerial = (serialNumber != null)
                ? serialNumber
                : CertificateBuildSupport.randomSerial();
        String resolvedSigAlg = (signatureAlgorithm != null)
                ? signatureAlgorithm
                : CertificateBuildSupport.defaultSignatureAlgorithm(issuerPrivateKey);

        X500Name issuerDn = X500Name.getInstance(
                issuerCertificate.getSubjectX500Principal().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuerDn,
                resolvedSerial,
                java.util.Date.from(resolvedNotBefore),
                java.util.Date.from(resolvedNotAfter),
                subject,
                SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded()));

        try {
            addExtensions(certBuilder);
            ContentSigner signer = new JcaContentSignerBuilder(resolvedSigAlg)
                    .build(issuerPrivateKey);
            X509CertificateHolder holder = certBuilder.build(signer);
            return CertificateBuildSupport.toX509Certificate(holder);
        } catch (GeneralSecurityException | OperatorCreationException | IOException e) {
            throw new IllegalStateException("Failed to build signed certificate", e);
        }
    }

    private void addExtensions(X509v3CertificateBuilder certBuilder)
            throws IOException, GeneralSecurityException {

        BasicConstraints bc = isCA
                ? (pathLength != null ? new BasicConstraints(pathLength) : new BasicConstraints(true))
                : new BasicConstraints(false);
        certBuilder.addExtension(Extension.basicConstraints, true, bc);

        if (!keyUsages.isEmpty()) {
            int bits = 0;
            for (KeyUsage u : keyUsages) {
                bits |= u.bcBit();
            }
            certBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    new org.bouncycastle.asn1.x509.KeyUsage(bits));
        }

        if (!extendedKeyUsages.isEmpty()) {
            org.bouncycastle.asn1.x509.KeyPurposeId[] purposes =
                    new org.bouncycastle.asn1.x509.KeyPurposeId[extendedKeyUsages.size()];
            int i = 0;
            for (ExtendedKeyUsage eku : extendedKeyUsages) {
                purposes[i++] = eku.purposeId();
            }
            certBuilder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(purposes));
        }

        if (sanBuilder != null && !sanBuilder.isEmpty()) {
            certBuilder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(sanBuilder.toGeneralNames()));
        }

        if (!crlDistributionPoints.isEmpty()) {
            DistributionPoint[] dps = new DistributionPoint[crlDistributionPoints.size()];
            for (int i = 0; i < crlDistributionPoints.size(); i++) {
                GeneralName uri = new GeneralName(
                        GeneralName.uniformResourceIdentifier, crlDistributionPoints.get(i));
                dps[i] = new DistributionPoint(
                        new DistributionPointName(new GeneralNames(uri)), null, null);
            }
            certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(dps));
        }

        if (!ocspUrls.isEmpty()) {
            AccessDescription[] descriptions = new AccessDescription[ocspUrls.size()];
            for (int i = 0; i < ocspUrls.size(); i++) {
                descriptions[i] = new AccessDescription(
                        AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrls.get(i)));
            }
            certBuilder.addExtension(
                    Extension.authorityInfoAccess, false,
                    AuthorityInformationAccess.getInstance(
                            new org.bouncycastle.asn1.DERSequence(descriptions)));
        }

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(subjectPublicKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(
                issuerCertificate.getPublicKey());
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
    }

    private static void requireState(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
