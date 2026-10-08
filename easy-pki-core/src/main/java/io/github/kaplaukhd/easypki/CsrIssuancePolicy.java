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

import java.security.PublicKey;
import java.util.Objects;
import java.util.function.Predicate;
import javax.security.auth.x500.X500Principal;

/**
 * Immutable CA authorization rules for {@link PkiCsr#issue(CsrRequest, CsrIssuancePolicy)}.
 * Subject and every requested SAN must be explicitly authorized. Requested extensions
 * are constrained to the selected profile; unknown extensions and attributes are rejected.
 * Callbacks must be safe for the application's concurrency model and are re-evaluated
 * on every issuance. Signature verification alone grants no identity or CA authority.
 *
 * <p>Issuance accepts RSA keys of at least 2048 bits, EC keys with field and order of
 * at least 256 bits, or Ed25519. CSR signatures must use SHA-256/384/512 with RSA or
 * ECDSA, Ed25519, or RSA-PSS with SHA-256/384/512 for both message and MGF1 digests.
 * General CSR reading and signature inspection remain separate from these rules.
 */
public final class CsrIssuancePolicy {
    private final CertificateProfile profile;
    private final Predicate<X500Principal> subject;
    private final Predicate<SubjectAlternativeName> san;
    private final Predicate<PublicKey> publicKey;
    private final Integer maximumPathLength;

    private CsrIssuancePolicy(Builder builder) {
        profile = builder.profile;
        subject = builder.subject;
        san = builder.san;
        publicKey = builder.publicKey;
        maximumPathLength = builder.maximumPathLength;
    }

    /** Starts rules for a TLS server, TLS client or intermediate CA, denying all identities. */
    public static Builder forProfile(CertificateProfile profile) {
        return new Builder(profile);
    }

    CertificateProfile profile() { return profile; }
    Integer maximumPathLength() { return maximumPathLength; }

    void authorize(CsrRequest request, java.util.List<SubjectAlternativeName> names) {
        if (!subject.test(request.getSubject())) {
            throw new IllegalArgumentException("CSR subject is not authorized by CA policy");
        }
        if (!publicKey.test(request.getPublicKey())) {
            throw new IllegalArgumentException("CSR public key is not authorized by CA policy");
        }
        for (SubjectAlternativeName name : names) {
            if (!san.test(name)) throw new IllegalArgumentException("CSR SAN is not authorized by CA policy");
        }
    }

    /** Mutable configuration; {@link #build()} snapshots rules into a reusable policy. */
    public static final class Builder {
        private final CertificateProfile profile;
        private Predicate<X500Principal> subject = ignored -> false;
        private Predicate<SubjectAlternativeName> san = ignored -> false;
        private Predicate<PublicKey> publicKey = ignored -> true;
        private Integer maximumPathLength;

        private Builder(CertificateProfile profile) {
            this.profile = Objects.requireNonNull(profile, "profile");
            if (profile == CertificateProfile.ROOT_CA) {
                throw new IllegalArgumentException("CSR issuance requires an issued certificate profile");
            }
        }

        /** Replaces subject authorization, including authorization of an explicitly empty DN. */
        public Builder allowSubject(Predicate<X500Principal> predicate) {
            subject = Objects.requireNonNull(predicate, "predicate");
            return this;
        }

        /** Replaces authorization for every SAN; IP values are canonical numeric literals. */
        public Builder allowSan(Predicate<SubjectAlternativeName> predicate) {
            san = Objects.requireNonNull(predicate, "predicate");
            return this;
        }

        /** Adds application key restrictions; cannot weaken the policy's minimum key strength. */
        public Builder allowPublicKey(Predicate<PublicKey> predicate) {
            publicKey = Objects.requireNonNull(predicate, "predicate");
            return this;
        }

        /**
         * Explicitly permits intermediate CA issuance with a finite maximum path length.
         * A smaller requested bound is retained; an omitted bound uses this maximum.
         * Only applicable to INTERMEDIATE_CA, never to a TLS profile.
         */
        public Builder allowCaRequests(int maximumPathLength) {
            if (profile != CertificateProfile.INTERMEDIATE_CA || maximumPathLength < 0) {
                throw new IllegalArgumentException("CA permission requires an intermediate profile and nonnegative path length");
            }
            this.maximumPathLength = maximumPathLength;
            return this;
        }

        /** Snapshots these rules; intermediate issuance requires explicit CA permission. */
        public CsrIssuancePolicy build() {
            if (profile == CertificateProfile.INTERMEDIATE_CA && maximumPathLength == null) {
                throw new IllegalStateException("Intermediate CSR policy requires explicit allowCaRequests(maximumPathLength)");
            }
            return new CsrIssuancePolicy(this);
        }
    }
}
