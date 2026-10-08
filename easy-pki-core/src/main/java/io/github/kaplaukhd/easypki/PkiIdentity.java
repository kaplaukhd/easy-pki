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
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Immutable snapshot of a signing handle, a leaf certificate and its ordered
 * presentation chain. The leaf is always first; a final root is optional.
 *
 * <p>Construction checks every supplied issuer name/signature link and proves
 * that the signer controls the leaf key by signing a fresh, domain-separated
 * random challenge. This performs one real signing operation, which may invoke
 * an external backend. No private key encoding is read. Verification uses the host JCA providers
 * and does not alter their global configuration.
 *
 * <p>This is not PKIX trust validation: expiry, CA constraints, revocation and
 * application policy are not checked, and no chain certificate becomes trusted.
 * Use the validation module with independently configured trust for acceptance.
 * Certificate encodings and the chain collection are copied. The signing
 * backend/key handle is application-owned and must retain a stable key and
 * algorithm; it is not cloned, closed or destroyed by this model.
 */
public final class PkiIdentity {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] CHALLENGE_PREFIX =
            "easy-pki identity key possession v1\0".getBytes(StandardCharsets.US_ASCII);

    private final PkiSigner signer;
    private final PrivateKey privateKey;
    private final List<X509Certificate> chain;

    private PkiIdentity(PkiSigner signer, PrivateKey privateKey, List<X509Certificate> chain) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.privateKey = privateKey;
        if (chain.isEmpty()) throw new IllegalArgumentException("identity chain must contain a leaf certificate");
        List<X509Certificate> snapshots = new ArrayList<>(chain.size());
        var seen = new HashSet<X509Certificate>();
        for (X509Certificate certificate : chain) {
            Objects.requireNonNull(certificate, "certificate");
            X509Certificate snapshot;
            try {
                snapshot = PkiCertificates.fromDer(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Cannot snapshot identity certificate", e);
            }
            if (!seen.add(snapshot)) throw new IllegalArgumentException("identity chain contains a duplicate certificate");
            snapshots.add(snapshot);
        }
        this.chain = List.copyOf(snapshots);
        verifyChainLinks();
        verifySignerKey();
    }

    /**
     * Creates an identity from an external signer and ordered issuers above the
     * leaf. The issuer array excludes the leaf and may omit the root.
     */
    public static PkiIdentity of(X509Certificate leaf, PkiSigner signer, X509Certificate... issuers) {
        return new PkiIdentity(signer, null, withLeaf(leaf, issuers));
    }

    /**
     * Creates an identity using default JCA signing for a supplied private-key
     * handle. The handle need not be exportable; choose the signer overload for
     * explicit algorithms or provider instances.
     */
    public static PkiIdentity of(X509Certificate leaf, PrivateKey key, X509Certificate... issuers) {
        Objects.requireNonNull(key, "key");
        return new PkiIdentity(PkiSigner.jca(key), key, withLeaf(leaf, issuers));
    }

    /** Creates an identity from an external signer and a full leaf-first chain. */
    public static PkiIdentity of(PkiSigner signer, List<X509Certificate> chain) {
        return new PkiIdentity(signer, null, List.copyOf(Objects.requireNonNull(chain, "chain")));
    }

    /**
     * Creates a checked identity from a loaded PKCS#12 identity bundle.
     * Trust-only bundles have no signing handle and are rejected.
     */
    public static PkiIdentity fromPkcs12(Pkcs12Bundle bundle) {
        Objects.requireNonNull(bundle, "bundle");
        PrivateKey key = bundle.getPrivateKey();
        if (key == null) throw new IllegalArgumentException("A trust-only PKCS#12 bundle is not a signing identity");
        return new PkiIdentity(PkiSigner.jca(key), key, bundle.getChain());
    }

    /** Returns the signing handle; its backend lifecycle remains application-owned. */
    public PkiSigner getSigner() { return signer; }

    /** Returns the leaf certificate, copied from its DER encoding at construction. */
    public X509Certificate getCertificate() { return chain.get(0); }

    /** Returns the immutable full presentation chain, with the leaf first. */
    public List<X509Certificate> getChain() { return chain; }

    /**
     * Returns the original JCA key handle when supplied via the private-key or
     * PKCS#12 factory. Identities created from a PkiSigner expose only that
     * signing operation. This accessor does not export or promise an encoding.
     */
    public Optional<PrivateKey> getPrivateKey() { return Optional.ofNullable(privateKey); }

    private static List<X509Certificate> withLeaf(X509Certificate leaf, X509Certificate[] issuers) {
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(issuers, "issuers");
        List<X509Certificate> chain = new ArrayList<>(issuers.length + 1);
        chain.add(leaf);
        chain.addAll(Arrays.asList(issuers.clone()));
        return chain;
    }

    private void verifyChainLinks() {
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate child = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (!child.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new IllegalArgumentException("Identity chain issuer name mismatch at index " + i);
            }
            try {
                child.verify(issuer.getPublicKey());
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException("Identity chain signature mismatch at index " + i, e);
            }
        }
    }

    private void verifySignerKey() {
        String algorithm = signer.signatureAlgorithm();
        AlgorithmIdentifier identifier = PkiSignerSupport.algorithmIdentifier(algorithm, signer.signatureParameters());
        byte[] challenge = Arrays.copyOf(CHALLENGE_PREFIX, CHALLENGE_PREFIX.length + 32);
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        System.arraycopy(random, 0, challenge, CHALLENGE_PREFIX.length, random.length);
        try {
            Signature verification;
            PSSParameterSpec pssParameters = null;
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(identifier.getAlgorithm())) {
                // The ASN.1 declaration also covers legacy digest-specific PSS aliases.
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
                parameters.init(identifier.getParameters().toASN1Primitive().getEncoded());
                verification = Signature.getInstance("RSASSA-PSS");
                pssParameters = parameters.getParameterSpec(PSSParameterSpec.class);
            } else {
                verification = Signature.getInstance(algorithm);
            }
            verification.initVerify(getCertificate().getPublicKey());
            if (pssParameters != null) verification.setParameter(pssParameters);
            // Keep the verifier's original challenge independent of backend mutation.
            byte[] signature = signer.sign(challenge.clone());
            if (signature == null || signature.length == 0) {
                throw new IllegalArgumentException("Identity signer returned an empty signature");
            }
            verification.update(challenge);
            if (!verification.verify(signature)) {
                throw new IllegalArgumentException("Identity signer does not match the leaf certificate key");
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException("Cannot verify identity signer against the leaf certificate key", e);
        }
    }
}
