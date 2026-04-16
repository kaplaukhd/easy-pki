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

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Fluent certificate validator.
 *
 * <p>Validates a certificate against a provided chain. The chain must
 * terminate either in a self-signed root or in one of the configured
 * {@linkplain #trustAnchors(X509Certificate...) trust anchors}.
 *
 * <h2>Example</h2>
 * <pre>{@code
 * ValidationResult result = CertValidator.of(leafCert)
 *     .chain(intermediate, root)
 *     .validate();
 *
 * if (!result.isValid()) {
 *     // inspect result.getErrors()
 * }
 * }</pre>
 *
 * <p>This initial version performs chain checks only: signatures, issuer /
 * subject DN continuity, validity windows and CA flags. Revocation (OCSP / CRL)
 * will arrive in subsequent releases.
 */
public final class CertValidator {

    private final X509Certificate certificate;
    private final List<X509Certificate> chain = new ArrayList<>();
    private final Set<X509Certificate> trustAnchors = new HashSet<>();
    private Instant evaluationTime;

    private CertValidator(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /** Starts validation of the given certificate. */
    public static CertValidator of(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        return new CertValidator(certificate);
    }

    /**
     * Supplies the chain of intermediates and (optionally) the root.
     * If the root is included and is self-signed, it becomes an implicit
     * trust anchor. Multiple calls accumulate.
     */
    public CertValidator chain(X509Certificate... chain) {
        Objects.requireNonNull(chain, "chain");
        for (X509Certificate c : chain) {
            this.chain.add(Objects.requireNonNull(c, "chain element"));
        }
        return this;
    }

    /** Overload that accepts a {@link List}. */
    public CertValidator chain(List<X509Certificate> chain) {
        Objects.requireNonNull(chain, "chain");
        for (X509Certificate c : chain) {
            this.chain.add(Objects.requireNonNull(c, "chain element"));
        }
        return this;
    }

    /**
     * Registers explicit trust anchors. If the chain does not terminate in a
     * self-signed root, the last certificate's issuer must be one of the
     * configured anchors and its signature must verify against that anchor.
     */
    public CertValidator trustAnchors(X509Certificate... anchors) {
        Objects.requireNonNull(anchors, "anchors");
        this.trustAnchors.addAll(Arrays.asList(anchors));
        return this;
    }

    /** Overload that accepts a collection. */
    public CertValidator trustAnchors(Collection<X509Certificate> anchors) {
        Objects.requireNonNull(anchors, "anchors");
        this.trustAnchors.addAll(anchors);
        return this;
    }

    /**
     * Sets the instant at which validity is evaluated. Default is now.
     * Useful for historical or future-dated checks.
     */
    public CertValidator at(Instant evaluationTime) {
        this.evaluationTime = Objects.requireNonNull(evaluationTime, "evaluationTime");
        return this;
    }

    /** Performs validation and returns the outcome. */
    public ValidationResult validate() {
        Instant now = (evaluationTime != null) ? evaluationTime : Instant.now();

        List<X509Certificate> path = new ArrayList<>(1 + chain.size());
        path.add(certificate);
        path.addAll(chain);

        List<ValidationError> errors = new ArrayList<>();
        boolean expired = false;
        boolean notYetValid = false;

        // Per-cert validity window.
        for (X509Certificate c : path) {
            Instant notBefore = c.getNotBefore().toInstant();
            Instant notAfter = c.getNotAfter().toInstant();
            if (now.isBefore(notBefore)) {
                notYetValid = true;
                errors.add(new ValidationError(
                        ValidationError.Code.NOT_YET_VALID,
                        "Certificate '" + subject(c) + "' is not valid until " + notBefore));
            }
            if (now.isAfter(notAfter)) {
                expired = true;
                errors.add(new ValidationError(
                        ValidationError.Code.EXPIRED,
                        "Certificate '" + subject(c) + "' expired on " + notAfter));
            }
        }

        // Chain: issuer DN continuity, signatures, intermediate CA flag.
        for (int i = 0; i < path.size() - 1; i++) {
            X509Certificate child = path.get(i);
            X509Certificate parent = path.get(i + 1);

            if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
                errors.add(new ValidationError(
                        ValidationError.Code.ISSUER_MISMATCH,
                        "Issuer of '" + subject(child) + "' does not match subject of '"
                                + subject(parent) + "'"));
            }

            try {
                child.verify(parent.getPublicKey());
            } catch (GeneralSecurityException e) {
                errors.add(new ValidationError(
                        ValidationError.Code.BROKEN_SIGNATURE,
                        "Signature of '" + subject(child) + "' does not verify against '"
                                + subject(parent) + "': " + e.getMessage()));
            }

            if (parent.getBasicConstraints() < 0) {
                errors.add(new ValidationError(
                        ValidationError.Code.NOT_A_CA,
                        "Certificate '" + subject(parent)
                                + "' is used as an issuer but lacks BasicConstraints cA=TRUE"));
            }
        }

        boolean trusted = determineTrust(path, errors);

        return ValidationResult.builder()
                .validationPath(Collections.unmodifiableList(path))
                .errors(Collections.unmodifiableList(errors))
                .expired(expired)
                .notYetValid(notYetValid)
                .trusted(trusted)
                .build();
    }

    private boolean determineTrust(List<X509Certificate> path, List<ValidationError> errors) {
        if (path.isEmpty()) {
            errors.add(new ValidationError(
                    ValidationError.Code.INCOMPLETE_CHAIN, "Validation chain is empty"));
            return false;
        }

        X509Certificate last = path.get(path.size() - 1);
        boolean selfSigned = last.getSubjectX500Principal().equals(last.getIssuerX500Principal());

        if (selfSigned) {
            if (trustAnchors.isEmpty() || trustAnchors.contains(last)) {
                try {
                    last.verify(last.getPublicKey());
                    return true;
                } catch (GeneralSecurityException e) {
                    errors.add(new ValidationError(
                            ValidationError.Code.BROKEN_SIGNATURE,
                            "Root '" + subject(last) + "' self-signature does not verify: "
                                    + e.getMessage()));
                    return false;
                }
            }
            errors.add(new ValidationError(
                    ValidationError.Code.UNTRUSTED_ROOT,
                    "Self-signed root '" + subject(last)
                            + "' is not among configured trust anchors"));
            return false;
        }

        for (X509Certificate anchor : trustAnchors) {
            if (anchor.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
                try {
                    last.verify(anchor.getPublicKey());
                    return true;
                } catch (GeneralSecurityException ignored) {
                    // keep looking
                }
            }
        }

        errors.add(new ValidationError(
                ValidationError.Code.UNTRUSTED_ROOT,
                "Chain does not terminate in a trusted anchor (last cert: '"
                        + subject(last) + "')"));
        return false;
    }

    private static String subject(X509Certificate c) {
        return c.getSubjectX500Principal().getName();
    }
}
