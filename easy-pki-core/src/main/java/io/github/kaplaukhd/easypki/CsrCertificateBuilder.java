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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Issues a CSR using explicit CA authorization and certificate profile preflight.
 * The request controls neither issuer, validity, serial number nor certificate
 * signature algorithm. Subject, key and extensions cannot be replaced after authorization.
 * Mutable builders are not thread-safe.
 */
public final class CsrCertificateBuilder {
    private final CsrRequest request;
    private final CsrIssuancePolicy policy;
    private PkiIdentity issuer;
    private Instant notBefore;
    private Instant notAfter;
    private Duration duration;
    private BigInteger serial;

    CsrCertificateBuilder(CsrRequest request, CsrIssuancePolicy policy) {
        this.request = Objects.requireNonNull(request, "request");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /** Sets the checked issuing identity, retaining its known chain for profile preflight. */
    public CsrCertificateBuilder issuer(PkiIdentity identity) {
        issuer = Objects.requireNonNull(identity, "identity");
        return this;
    }

    /** Sets notBefore; otherwise the instant at the start of build is used. */
    public CsrCertificateBuilder validFrom(Instant instant) {
        notBefore = Objects.requireNonNull(instant, "instant");
        return this;
    }

    /** Sets positive validity duration; replaces validUntil. */
    public CsrCertificateBuilder validFor(Duration value) {
        Objects.requireNonNull(value, "value");
        if (value.isNegative() || value.isZero()) throw new IllegalArgumentException("Validity duration must be positive");
        duration = value;
        notAfter = null;
        return this;
    }

    /** Sets notAfter; replaces validFor. */
    public CsrCertificateBuilder validUntil(Instant instant) {
        notAfter = Objects.requireNonNull(instant, "instant");
        duration = null;
        return this;
    }

    /** Overrides the random positive serial with a value from 1 through 2^159 - 1. */
    public CsrCertificateBuilder serialNumber(BigInteger value) {
        serial = CertificateBuildSupport.validateSerialNumber(value);
        return this;
    }

    /**
     * Verifies proof of possession, authorizes all requested identities and extensions,
     * checks the issuer profile and signs. Every failure in these checks precedes CA signing.
     * Authorization callbacks run again on each call; changes to this builder from a callback
     * affect only later calls. No PKIX trust or external ownership validation is inferred.
     */
    public X509Certificate build() {
        // Snapshot all mutable CA configuration before executing application callbacks.
        PkiIdentity identity = issuer;
        Instant start = notBefore != null ? notBefore : Instant.now();
        Instant end = notAfter;
        Duration lifetime = duration;
        BigInteger number = serial;
        if (identity == null) throw new IllegalStateException("CSR issuance requires an issuer identity");
        if (end == null && lifetime == null) throw new IllegalStateException("CSR issuance requires explicit validity");
        request.requireValidSignature();
        CsrPolicySupport.Approved approved = CsrPolicySupport.approve(request, policy);
        SignedCertificateBuilder certificate = PkiCertificate.signed().profile(policy.profile())
                .subject(request.getSubject()).publicKey(request.getPublicKey()).issuer(identity).validFrom(start);
        if (end != null) certificate.validUntil(end); else certificate.validFor(lifetime);
        if (number != null) certificate.serialNumber(number);
        if (approved.pathLength() != null) certificate.pathLength(approved.pathLength());
        certificate.keyUsage(approved.usages().toArray(KeyUsage[]::new));
        if (!approved.names().isEmpty()) certificate.san(s -> {
            for (SubjectAlternativeName name : approved.names()) {
                switch (name.type()) {
                    case DNS -> s.dns(name.value());
                    case IP_ADDRESS -> s.ip(name.value());
                    case EMAIL -> s.email(name.value());
                    case URI -> s.uri(name.value());
                    default -> throw new IllegalStateException("Unsupported authorized SAN");
                }
            }
        });
        return certificate.build();
    }
}
