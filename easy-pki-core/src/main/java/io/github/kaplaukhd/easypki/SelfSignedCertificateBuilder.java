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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Fluent builder for self-signed X.509 certificates.
 *
 * <p>Obtain an instance via {@link PkiCertificate#selfSigned()}. The same key
 * pair is used both as the certificate's public key and to sign it. Typical use:
 *
 * <pre>{@code
 * X509Certificate cert = PkiCertificate.selfSigned()
 *     .subject("CN=example.com")
 *     .keyPair(keys)
 *     .validFor(Duration.ofDays(365))
 *     .build();
 * }</pre>
 *
 * <p>Defaults applied automatically:
 * <ul>
 *   <li>Random 20-byte positive serial number (RFC 5280 §4.1.2.2).</li>
 *   <li>Signature algorithm {@code SHA256withRSA} for RSA keys,
 *       {@code SHA256withECDSA} for EC keys.</li>
 *   <li>{@code notBefore} = now (when not explicitly set).</li>
 *   <li>SubjectKeyIdentifier and AuthorityKeyIdentifier extensions derived
 *       from the public key.</li>
 * </ul>
 */
public final class SelfSignedCertificateBuilder {

    private X500Name subject;
    private KeyPair keyPair;

    private Instant notBefore;
    private Instant notAfter;
    private Duration validFor;

    private BigInteger serialNumber;
    private String signatureAlgorithm;

    private boolean isCA;
    private Integer pathLength;

    private final Set<KeyUsage> keyUsages = EnumSet.noneOf(KeyUsage.class);

    SelfSignedCertificateBuilder() {
        // Package-private: use PkiCertificate.selfSigned().
    }

    /**
     * Sets the subject distinguished name from an RFC 4514 string
     * (e.g. {@code "CN=example.com, O=Corp, C=RU"}).
     */
    public SelfSignedCertificateBuilder subject(String rfc4514) {
        Objects.requireNonNull(rfc4514, "rfc4514");
        this.subject = new X500Name(rfc4514);
        return this;
    }

    /**
     * Sets the subject distinguished name using a fluent sub-builder:
     * <pre>{@code .subject(dn -> dn.cn("example.com").o("Corp").c("RU"))}</pre>
     */
    public SelfSignedCertificateBuilder subject(Consumer<DnBuilder> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        DnBuilder dn = new DnBuilder();
        configurer.accept(dn);
        this.subject = dn.toX500Name();
        return this;
    }

    /**
     * Sets the key pair whose public key becomes the certificate's subject
     * public key and whose private key is used to sign the certificate.
     */
    public SelfSignedCertificateBuilder keyPair(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        return this;
    }

    /**
     * Sets the validity duration starting from {@link #validFrom(Instant)}
     * (or now, if not set). Mutually exclusive with {@link #validUntil(Instant)}
     * — whichever is called last wins.
     */
    public SelfSignedCertificateBuilder validFor(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        if (duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(
                    "validFor duration must be positive, got " + duration);
        }
        this.validFor = duration;
        this.notAfter = null;
        return this;
    }

    /** Sets the {@code notBefore} field explicitly. Default is now. */
    public SelfSignedCertificateBuilder validFrom(Instant notBefore) {
        this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
        return this;
    }

    /**
     * Sets the {@code notAfter} field explicitly. Mutually exclusive with
     * {@link #validFor(Duration)} — whichever is called last wins.
     */
    public SelfSignedCertificateBuilder validUntil(Instant notAfter) {
        this.notAfter = Objects.requireNonNull(notAfter, "notAfter");
        this.validFor = null;
        return this;
    }

    /**
     * Overrides the serial number. By default a random, positive, 20-byte
     * serial is generated for every {@link #build()} call (RFC 5280 §4.1.2.2).
     * Useful for deterministic fixtures in tests.
     */
    public SelfSignedCertificateBuilder serialNumber(BigInteger serialNumber) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        if (serialNumber.signum() <= 0) {
            throw new IllegalArgumentException(
                    "serialNumber must be positive, got " + serialNumber);
        }
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * Overrides the JCA signature algorithm name (e.g. {@code "SHA384withRSA"}).
     * By default the algorithm is derived from the key type: RSA keys use
     * {@code SHA256withRSA}, EC keys use {@code SHA256withECDSA}.
     */
    public SelfSignedCertificateBuilder signatureAlgorithm(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        this.signatureAlgorithm = algorithm;
        return this;
    }

    /**
     * Marks the certificate as a CA — adds {@code BasicConstraints(cA=TRUE)}.
     * Default is {@code false}.
     */
    public SelfSignedCertificateBuilder isCA(boolean ca) {
        this.isCA = ca;
        return this;
    }

    /**
     * Sets the maximum intermediate-CA path length in the {@code BasicConstraints}
     * extension. Implies {@link #isCA(boolean) isCA(true)}.
     */
    public SelfSignedCertificateBuilder pathLength(int pathLength) {
        if (pathLength < 0) {
            throw new IllegalArgumentException(
                    "pathLength must be >= 0, got " + pathLength);
        }
        this.pathLength = pathLength;
        this.isCA = true;
        return this;
    }

    /**
     * Adds {@code KeyUsage} bits. Multiple calls accumulate; duplicates are
     * ignored.
     */
    public SelfSignedCertificateBuilder keyUsage(KeyUsage... usages) {
        Objects.requireNonNull(usages, "usages");
        for (KeyUsage usage : usages) {
            keyUsages.add(Objects.requireNonNull(usage, "usage"));
        }
        return this;
    }

    /**
     * Builds and signs the certificate.
     *
     * @throws IllegalStateException if required fields are missing.
     */
    public X509Certificate build() {
        requireState(subject != null, "subject is required");
        requireState(keyPair != null, "keyPair is required");
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
                : CertificateBuildSupport.defaultSignatureAlgorithm(keyPair.getPrivate());

        PublicKey publicKey = keyPair.getPublic();

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,
                resolvedSerial,
                java.util.Date.from(resolvedNotBefore),
                java.util.Date.from(resolvedNotAfter),
                subject, // self-signed: issuer == subject
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        try {
            addExtensions(certBuilder, publicKey);
            ContentSigner signer = new JcaContentSignerBuilder(resolvedSigAlg)
                    .build(keyPair.getPrivate());
            X509CertificateHolder holder = certBuilder.build(signer);
            return CertificateBuildSupport.toX509Certificate(holder);
        } catch (GeneralSecurityException | OperatorCreationException | java.io.IOException e) {
            throw new IllegalStateException("Failed to build self-signed certificate", e);
        }
    }

    private void addExtensions(X509v3CertificateBuilder certBuilder, PublicKey publicKey)
            throws java.io.IOException, GeneralSecurityException {

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

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(publicKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        // Self-signed: AKI is derived from the same public key.
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(publicKey);
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
    }

    private static void requireState(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
