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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

/**
 * Fluent builder for a signed PKCS#10 certificate signing request.
 * Obtain an instance via {@link PkiCsr#create()}.
 *
 * <pre>{@code
 * CsrRequest request = PkiCsr.create()
 *     .subject("CN=api.example.com,O=Example")
 *     .keyPair(keys)
 *     .san(s -> s.dns("api.example.com"))
 *     .build();
 * }</pre>
 *
 * <p>The subject must be supplied explicitly; an empty subject is supported.
 * Extensions are included only when requested. No certificate profile, key
 * identifiers, validity or issuer authority is inferred. Requested CA flags
 * and usages are requests for an issuer to evaluate, not authorization to issue.
 * Each build verifies the signature against the public key embedded in the CSR.
 */
public final class CsrBuilder {
    private X500Name subject;
    private KeyPair keyPair;
    private PublicKey signerPublicKey;
    private PkiSigner pkiSigner;
    private String signatureAlgorithm;
    private SanBuilder sanBuilder;
    private final Set<KeyUsage> keyUsages = EnumSet.noneOf(KeyUsage.class);
    private final Set<ExtendedKeyUsage> extendedKeyUsages = EnumSet.noneOf(ExtendedKeyUsage.class);
    private final Map<String, CsrExtension> extensions = new LinkedHashMap<>();
    private boolean caConfigured;
    private boolean ca;
    private Integer pathLength;

    CsrBuilder() {
        // Package-private: use PkiCsr.create().
    }

    /** Sets the subject using the JCA RFC 2253/4514 DN convention. An empty DN is allowed. */
    public CsrBuilder subject(String rfc4514) {
        return subject(new X500Principal(Objects.requireNonNull(rfc4514, "rfc4514")));
    }

    /** Copies the subject principal's DER without reordering RDNs or converting values through text. */
    public CsrBuilder subject(X500Principal principal) {
        this.subject = X500Name.getInstance(Objects.requireNonNull(principal, "principal").getEncoded());
        return this;
    }

    /** Sets the subject with a fluent DN builder, preserving display order and escaping literal values. */
    public CsrBuilder subject(Consumer<DnBuilder> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        DnBuilder dn = new DnBuilder();
        configurer.accept(dn);
        this.subject = dn.toX500Name();
        return this;
    }

    /**
     * Uses this pair's public key in the request and its private key to sign.
     * Replaces an explicit signer and uses the JCA signing adapter without exporting the private key.
     */
    public CsrBuilder keyPair(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        this.signerPublicKey = null;
        this.pkiSigner = null;
        return this;
    }

    /**
     * Uses an external signer and its matching public key, replacing {@link #keyPair(KeyPair)}.
     * The signer owns its algorithm; this cannot be combined with {@link #signatureAlgorithm(String)}.
     */
    public CsrBuilder signer(PublicKey publicKey, PkiSigner signer) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(signer, "signer");
        requireState(signatureAlgorithm == null, "Configure the signature algorithm on PkiSigner, not the builder");
        this.signerPublicKey = publicKey;
        this.pkiSigner = signer;
        this.keyPair = null;
        return this;
    }

    /**
     * Overrides the key-pair route's JCA signature name. Defaults are SHA256withRSA,
     * SHA256withECDSA or Ed25519 according to the key type. Configure explicit
     * signers, including parameterized RSA-PSS signers, on the signer itself.
     */
    public CsrBuilder signatureAlgorithm(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        requireState(pkiSigner == null, "Configure the signature algorithm on PkiSigner, not the builder");
        this.signatureAlgorithm = algorithm;
        return this;
    }

    /**
     * Adds requested SAN entries in insertion order, including duplicates, to a
     * noncritical extension. Text must be ASCII; use DNS A-labels for international names.
     */
    public CsrBuilder san(Consumer<SanBuilder> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        if (sanBuilder == null) sanBuilder = new SanBuilder();
        configurer.accept(sanBuilder);
        return this;
    }

    /** Adds requested key usage bits to a critical extension. Calls accumulate and duplicate bits are ignored. */
    public CsrBuilder keyUsage(KeyUsage... usages) {
        Objects.requireNonNull(usages, "usages");
        for (KeyUsage usage : usages) keyUsages.add(Objects.requireNonNull(usage, "usage"));
        return this;
    }

    /** Adds requested purposes to a noncritical extended-key-usage extension. Calls accumulate and duplicates are ignored. */
    public CsrBuilder extendedKeyUsage(ExtendedKeyUsage... purposes) {
        Objects.requireNonNull(purposes, "purposes");
        for (ExtendedKeyUsage purpose : purposes) {
            extendedKeyUsages.add(Objects.requireNonNull(purpose, "purpose"));
        }
        return this;
    }

    /** Requests critical BasicConstraints with the given CA flag; this grants no issuer authority. */
    public CsrBuilder isCA(boolean ca) {
        this.ca = ca;
        this.caConfigured = true;
        return this;
    }

    /** Requests a nonnegative CA path length and implies {@code isCA(true)}. */
    public CsrBuilder pathLength(int pathLength) {
        if (pathLength < 0) throw new IllegalArgumentException("pathLength must be >= 0, got " + pathLength);
        this.pathLength = pathLength;
        this.ca = true;
        this.caConfigured = true;
        return this;
    }

    /**
     * Adds a raw requested extension. Its value is the DER encoding inside the
     * extension's OCTET STRING. Duplicate OIDs, including collisions with fluent
     * extension helpers, are rejected before signing. No custom extension is
     * automatically approved for issuance.
     */
    public CsrBuilder extension(CsrExtension extension) {
        Objects.requireNonNull(extension, "extension");
        CsrRequest.requireDer(extension.getValue());
        if (extensions.putIfAbsent(extension.getOid(), extension) != null) {
            throw new IllegalArgumentException("Duplicate requested extension: " + extension.getOid());
        }
        return this;
    }

    /**
     * Builds a new immutable request and verifies possession of its embedded public key.
     *
     * @return the signed request
     * @throws IllegalStateException if subject or signing key is missing, settings
     *         conflict, or signing fails
     * @throws IllegalArgumentException if extensions are invalid or the resulting
     *         signature does not verify against the embedded public key
     */
    public CsrRequest build() {
        requireState(subject != null, "subject is required (an explicitly empty subject is allowed)");
        requireState(keyPair != null || pkiSigner != null, "keyPair or signer(publicKey, signer) is required");
        requireState(pathLength == null || ca, "pathLength requires isCA(true)");
        if (sanBuilder != null) sanBuilder.requireAsciiValues();
        PublicKey publicKey = pkiSigner != null ? signerPublicKey : keyPair.getPublic();
        PkiSigner resolvedSigner = pkiSigner != null ? pkiSigner : PkiSigner.jca(keyPair.getPrivate(),
                signatureAlgorithm != null ? signatureAlgorithm
                        : CertificateBuildSupport.defaultSignatureAlgorithm(keyPair.getPrivate()));
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
        try {
            ExtensionsGenerator requested = requestedExtensions();
            if (!requested.isEmpty()) {
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, requested.generate());
            }
            CsrRequest request = CsrRequest.fromDer(builder.build(PkiSignerSupport.contentSigner(resolvedSigner)).getEncoded());
            request.requireValidSignature();
            return request;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to build certificate signing request", e);
        }
    }

    private ExtensionsGenerator requestedExtensions() throws IOException {
        ExtensionsGenerator requested = new ExtensionsGenerator();
        if (caConfigured) {
            BasicConstraints constraints = ca
                    ? (pathLength != null ? new BasicConstraints(pathLength) : new BasicConstraints(true))
                    : new BasicConstraints(false);
            requested.addExtension(Extension.basicConstraints, true, constraints);
        }
        if (!keyUsages.isEmpty()) {
            int bits = 0;
            for (KeyUsage usage : keyUsages) bits |= usage.bcBit();
            requested.addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(bits));
        }
        if (!extendedKeyUsages.isEmpty()) {
            KeyPurposeId[] purposes = extendedKeyUsages.stream().map(ExtendedKeyUsage::purposeId).toArray(KeyPurposeId[]::new);
            requested.addExtension(Extension.extendedKeyUsage, false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(purposes));
        }
        if (sanBuilder != null && !sanBuilder.isEmpty()) {
            requested.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanBuilder.toGeneralNames()));
        }
        for (CsrExtension extension : extensions.values()) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extension.getOid());
            if (requested.hasExtension(oid)) {
                throw new IllegalArgumentException("Duplicate requested extension: " + extension.getOid());
            }
            requested.addExtension(oid, extension.isCritical(), extension.getValue());
        }
        return requested;
    }

    private static void requireState(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
