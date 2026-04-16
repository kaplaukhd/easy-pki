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
package io.github.kaplaukhd.easypki.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.github.kaplaukhd.easypki.validation.CrlBuilder;
import io.github.kaplaukhd.easypki.validation.PkiCrl;
import io.github.kaplaukhd.easypki.validation.RevocationReason;

/**
 * A self-contained, in-memory PKI useful for unit and integration tests.
 *
 * <pre>{@code
 * TestPki pki = TestPki.create()
 *     .withRootCa("CN=Test Root CA")
 *     .withIntermediateCa("CN=Test Issuing CA")
 *     .build();
 *
 * X509Certificate server = pki.issueCert()
 *     .subject("CN=localhost")
 *     .san("localhost", "127.0.0.1")
 *     .build();
 *
 * IssuedCert client = pki.issueCert()
 *     .subject("CN=test-client")
 *     .issue();   // access both certificate and private key
 * }</pre>
 */
public final class TestPki {

    private final KeyPair rootKeys;
    private final X509Certificate rootCa;
    private final KeyPair intermediateKeys;      // nullable — may be absent
    private final X509Certificate intermediateCa; // nullable — may be absent

    private final Map<BigInteger, RevocationEntry> revocations = new LinkedHashMap<>();

    TestPki(KeyPair rootKeys,
            X509Certificate rootCa,
            KeyPair intermediateKeys,
            X509Certificate intermediateCa) {
        this.rootKeys = Objects.requireNonNull(rootKeys, "rootKeys");
        this.rootCa = Objects.requireNonNull(rootCa, "rootCa");
        this.intermediateKeys = intermediateKeys;
        this.intermediateCa = intermediateCa;
    }

    /** Starts a new PKI builder. */
    public static TestPkiBuilder create() {
        return new TestPkiBuilder();
    }

    /** Starts a new leaf-certificate issuance builder. */
    public TestIssueCertBuilder issueCert() {
        return new TestIssueCertBuilder(this);
    }

    // ---------- accessors ----------

    public X509Certificate getRootCa() {
        return rootCa;
    }

    public KeyPair getRootKeys() {
        return rootKeys;
    }

    public PrivateKey getRootPrivateKey() {
        return rootKeys.getPrivate();
    }

    /** The intermediate CA if configured, otherwise {@code null}. */
    public X509Certificate getIntermediateCa() {
        return intermediateCa;
    }

    /** The intermediate CA key pair if configured, otherwise {@code null}. */
    public KeyPair getIntermediateKeys() {
        return intermediateKeys;
    }

    /** {@code true} if an intermediate CA was configured. */
    public boolean hasIntermediate() {
        return intermediateCa != null;
    }

    /**
     * The effective issuer for {@link #issueCert()} — the intermediate CA if
     * configured, otherwise the root.
     */
    public X509Certificate getIssuerCa() {
        return intermediateCa != null ? intermediateCa : rootCa;
    }

    /** Private key matching {@link #getIssuerCa()}. */
    public PrivateKey getIssuerPrivateKey() {
        return intermediateKeys != null ? intermediateKeys.getPrivate() : rootKeys.getPrivate();
    }

    /**
     * Chain from the effective issuer up to the root, in PKI order (leaf-most
     * first). For an intermediate-less PKI this is just {@code [root]}; with
     * an intermediate it is {@code [intermediate, root]}.
     */
    public List<X509Certificate> getChain() {
        return intermediateCa != null
                ? List.of(intermediateCa, rootCa)
                : List.of(rootCa);
    }

    /** Trust anchors suitable for a client's trust store. */
    public List<X509Certificate> getTrustAnchors() {
        return List.of(rootCa);
    }

    // ---------- revocation ----------

    /**
     * Marks {@code certificate} as revoked with the given reason and
     * {@code revocationDate = now}. The revocation is reflected in the CRL
     * returned by {@link #getCrl()}.
     */
    public void revoke(X509Certificate certificate, RevocationReason reason) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(reason, "reason");
        revocations.put(
                certificate.getSerialNumber(),
                new RevocationEntry(reason, Instant.now()));
    }

    /** {@code true} if the given certificate has been revoked in this PKI. */
    public boolean isRevoked(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        return revocations.containsKey(certificate.getSerialNumber());
    }

    /**
     * Returns a freshly-built CRL issued by the effective issuer CA, covering
     * every revocation registered through {@link #revoke(X509Certificate,
     * RevocationReason)}. Rebuilt on each call so the result always reflects
     * the current state.
     */
    public X509CRL getCrl() {
        CrlBuilder builder = PkiCrl.issued()
                .issuer(getIssuerCa(), getIssuerPrivateKey())
                .nextUpdate(Duration.ofHours(24));
        for (Map.Entry<BigInteger, RevocationEntry> e : revocations.entrySet()) {
            RevocationEntry entry = e.getValue();
            builder.revoke(e.getKey(), entry.reason(), entry.revokedAt());
        }
        return builder.build();
    }

    /**
     * Starts a local in-memory OCSP responder backed by this PKI. The caller
     * owns the lifecycle — close it (or use try-with-resources) when done.
     *
     * <pre>{@code
     * try (TestOcspResponder ocsp = pki.startOcspResponder()) {
     *     X509Certificate cert = pki.issueCert()
     *         .subject("CN=host")
     *         .ocsp(ocsp.getUrl())
     *         .build();
     *     // ...
     * }
     * }</pre>
     */
    public TestOcspResponder startOcspResponder() {
        try {
            return new TestOcspResponder(this);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException("Failed to start OCSP responder", e);
        }
    }

    // Package-private: responder queries the current revocation state.
    RevocationEntry revocationOf(BigInteger serial) {
        return revocations.get(serial);
    }

    record RevocationEntry(RevocationReason reason, Instant revokedAt) {}
}
