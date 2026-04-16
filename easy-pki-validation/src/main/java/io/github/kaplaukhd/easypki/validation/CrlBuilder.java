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
package io.github.kaplaukhd.easypki.validation;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Fluent builder for {@link X509CRL} objects.
 *
 * <p>Obtained via {@link PkiCrl#issued()}. The builder always adds an
 * {@code AuthorityKeyIdentifier} and a {@code CRLNumber} extension. Defaults:
 * <ul>
 *   <li>{@code thisUpdate} = now</li>
 *   <li>{@code crlNumber} = 128-bit random positive integer</li>
 *   <li>Signature algorithm derived from the issuer private key
 *       (RSA → {@code SHA256withRSA}, EC → {@code SHA256withECDSA})</li>
 * </ul>
 */
public final class CrlBuilder {

    private X509Certificate issuerCertificate;
    private PrivateKey issuerPrivateKey;

    private Instant thisUpdate;
    private Instant nextUpdate;
    private Duration nextUpdateAfter;

    private BigInteger crlNumber;
    private String signatureAlgorithm;

    private final List<RevokedEntry> revoked = new ArrayList<>();

    CrlBuilder() {
        // Package-private — use PkiCrl.issued().
    }

    /**
     * Sets the issuing CA. Its subject DN becomes the CRL's issuer, its public
     * key is used to derive the AuthorityKeyIdentifier, and its private key
     * signs the CRL.
     */
    public CrlBuilder issuer(X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        this.issuerPrivateKey = Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey");
        return this;
    }

    /** Sets the {@code thisUpdate} timestamp explicitly. Default is now. */
    public CrlBuilder thisUpdate(Instant thisUpdate) {
        this.thisUpdate = Objects.requireNonNull(thisUpdate, "thisUpdate");
        return this;
    }

    /**
     * Sets the {@code nextUpdate} timestamp as an offset from {@code thisUpdate}
     * (or now, if {@code thisUpdate} has not been set). Mutually exclusive
     * with {@link #nextUpdate(Instant)}.
     */
    public CrlBuilder nextUpdate(Duration after) {
        Objects.requireNonNull(after, "after");
        if (after.isNegative() || after.isZero()) {
            throw new IllegalArgumentException(
                    "nextUpdate offset must be positive, got " + after);
        }
        this.nextUpdateAfter = after;
        this.nextUpdate = null;
        return this;
    }

    /**
     * Sets the {@code nextUpdate} timestamp explicitly. Mutually exclusive with
     * {@link #nextUpdate(Duration)}.
     */
    public CrlBuilder nextUpdate(Instant nextUpdate) {
        this.nextUpdate = Objects.requireNonNull(nextUpdate, "nextUpdate");
        this.nextUpdateAfter = null;
        return this;
    }

    /** Overrides the random default CRL number. */
    public CrlBuilder crlNumber(BigInteger number) {
        Objects.requireNonNull(number, "number");
        if (number.signum() <= 0) {
            throw new IllegalArgumentException(
                    "CRL number must be positive, got " + number);
        }
        this.crlNumber = number;
        return this;
    }

    /** Overrides the JCA signature algorithm. Default is derived from the issuer key. */
    public CrlBuilder signatureAlgorithm(String algorithm) {
        this.signatureAlgorithm = Objects.requireNonNull(algorithm, "algorithm");
        return this;
    }

    /**
     * Marks a certificate as revoked with the given reason and {@code revokedAt = now}.
     */
    public CrlBuilder revoke(X509Certificate certificate, RevocationReason reason) {
        Objects.requireNonNull(certificate, "certificate");
        return revoke(certificate.getSerialNumber(), reason, Instant.now());
    }

    /** Marks a serial number as revoked with the given reason. */
    public CrlBuilder revoke(BigInteger serialNumber, RevocationReason reason) {
        return revoke(serialNumber, reason, Instant.now());
    }

    /** Marks a serial number as revoked at a specific time. */
    public CrlBuilder revoke(BigInteger serialNumber, RevocationReason reason, Instant revokedAt) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(revokedAt, "revokedAt");
        revoked.add(new RevokedEntry(serialNumber, reason, revokedAt));
        return this;
    }

    /**
     * Builds and signs the CRL.
     *
     * @throws IllegalStateException if required fields are missing.
     */
    public X509CRL build() {
        if (issuerCertificate == null || issuerPrivateKey == null) {
            throw new IllegalStateException("issuer(certificate, privateKey) is required");
        }
        if (nextUpdateAfter == null && nextUpdate == null) {
            throw new IllegalStateException(
                    "either nextUpdate(Duration) or nextUpdate(Instant) is required");
        }

        Instant resolvedThisUpdate = (thisUpdate != null) ? thisUpdate : Instant.now();
        Instant resolvedNextUpdate = (nextUpdate != null)
                ? nextUpdate
                : resolvedThisUpdate.plus(nextUpdateAfter);

        if (!resolvedNextUpdate.isAfter(resolvedThisUpdate)) {
            throw new IllegalStateException(
                    "nextUpdate (" + resolvedNextUpdate + ") must be after thisUpdate ("
                            + resolvedThisUpdate + ")");
        }

        BigInteger resolvedCrlNumber = (crlNumber != null) ? crlNumber : CrlBuildSupport.randomCrlNumber();
        String resolvedSigAlg = (signatureAlgorithm != null)
                ? signatureAlgorithm
                : CrlBuildSupport.defaultSignatureAlgorithm(issuerPrivateKey);

        X500Name issuerDn = X500Name.getInstance(
                issuerCertificate.getSubjectX500Principal().getEncoded());
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerDn, Date.from(resolvedThisUpdate));
        builder.setNextUpdate(Date.from(resolvedNextUpdate));

        for (RevokedEntry entry : revoked) {
            builder.addCRLEntry(
                    entry.serial,
                    Date.from(entry.revokedAt),
                    entry.reason.crlReasonCode());
        }

        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extUtils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
            builder.addExtension(
                    Extension.cRLNumber,
                    false,
                    new CRLNumber(resolvedCrlNumber));

            ContentSigner signer = new JcaContentSignerBuilder(resolvedSigAlg)
                    .build(issuerPrivateKey);
            X509CRLHolder holder = builder.build(signer);
            return CrlBuildSupport.toX509Crl(holder);
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("Failed to build CRL", e);
        }
    }

    private record RevokedEntry(BigInteger serial, RevocationReason reason, Instant revokedAt) {}
}
