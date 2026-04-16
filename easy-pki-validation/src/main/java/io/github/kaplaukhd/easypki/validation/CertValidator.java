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
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
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
 * <h2>Chain-only validation</h2>
 * <pre>{@code
 * ValidationResult r = CertValidator.of(leaf).chain(intermediate, root).validate();
 * }</pre>
 *
 * <h2>With CRL-based revocation</h2>
 * <pre>{@code
 * CertValidator.of(leaf).chain(intermediate, root).crl(fetchedCrl).validate();
 * }</pre>
 */
public final class CertValidator {

    private final X509Certificate certificate;
    private final List<X509Certificate> chain = new ArrayList<>();
    private final Set<X509Certificate> trustAnchors = new HashSet<>();
    private final List<X509CRL> crls = new ArrayList<>();
    private boolean crlCheckEnabled;
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

    /**
     * Enables CRL-based revocation checking against the supplied CRLs.
     * For each non-anchor certificate in the path, a CRL whose issuer DN
     * matches the certificate's issuer DN and whose signature verifies
     * against the issuer's public key is applied.
     *
     * <p>Multiple calls accumulate CRLs. If no CRL covers a given
     * certificate, a {@link ValidationError.Code#REVOCATION_UNKNOWN}
     * error is recorded.
     */
    public CertValidator crl(X509CRL... crls) {
        Objects.requireNonNull(crls, "crls");
        this.crlCheckEnabled = true;
        for (X509CRL crl : crls) {
            this.crls.add(Objects.requireNonNull(crl, "crl"));
        }
        return this;
    }

    /** List overload of {@link #crl(X509CRL...)}. */
    public CertValidator crl(List<X509CRL> crls) {
        Objects.requireNonNull(crls, "crls");
        this.crlCheckEnabled = true;
        for (X509CRL crl : crls) {
            this.crls.add(Objects.requireNonNull(crl, "crl"));
        }
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

        ValidationResult.Builder builder = ValidationResult.builder()
                .validationPath(Collections.unmodifiableList(path))
                .expired(expired)
                .notYetValid(notYetValid)
                .trusted(trusted);

        if (crlCheckEnabled) {
            checkRevocation(path, errors, now, builder);
        }

        builder.errors(Collections.unmodifiableList(errors));
        return builder.build();
    }

    private void checkRevocation(List<X509Certificate> path,
                                 List<ValidationError> errors,
                                 Instant now,
                                 ValidationResult.Builder builder) {

        for (int i = 0; i < path.size() - 1; i++) {
            X509Certificate subject = path.get(i);
            X509Certificate issuer = path.get(i + 1);

            X509CRL applicable = findApplicableCrl(subject, issuer, now, errors);
            if (applicable == null) {
                errors.add(new ValidationError(
                        ValidationError.Code.REVOCATION_UNKNOWN,
                        "No valid CRL available for '" + subject(subject) + "'"));
                continue;
            }

            X509CRLEntry entry = applicable.getRevokedCertificate(subject);
            if (entry == null) {
                continue;
            }

            RevocationReason reason = extractReason(entry);
            Instant revokedAt = entry.getRevocationDate().toInstant();
            errors.add(new ValidationError(
                    ValidationError.Code.REVOKED,
                    "Certificate '" + subject(subject) + "' was revoked on "
                            + revokedAt + " (" + reason + ")"));
            if (!builder.isRevoked()) {
                builder.revoked(reason, revokedAt);
            }
        }
    }

    private X509CRL findApplicableCrl(X509Certificate subject,
                                      X509Certificate issuer,
                                      Instant now,
                                      List<ValidationError> errors) {
        for (X509CRL crl : crls) {
            if (!crl.getIssuerX500Principal().equals(subject.getIssuerX500Principal())) {
                continue;
            }
            if (crl.getThisUpdate() != null && crl.getThisUpdate().toInstant().isAfter(now)) {
                continue;
            }
            if (crl.getNextUpdate() != null && crl.getNextUpdate().toInstant().isBefore(now)) {
                errors.add(new ValidationError(
                        ValidationError.Code.CRL_UNAVAILABLE,
                        "CRL for '" + subject(issuer) + "' is expired (nextUpdate="
                                + crl.getNextUpdate().toInstant() + ")"));
                continue;
            }
            try {
                crl.verify(issuer.getPublicKey());
            } catch (GeneralSecurityException e) {
                errors.add(new ValidationError(
                        ValidationError.Code.CRL_UNAVAILABLE,
                        "CRL signature for '" + subject(issuer) + "' does not verify: "
                                + e.getMessage()));
                continue;
            }
            return crl;
        }
        return null;
    }

    private static RevocationReason extractReason(X509CRLEntry entry) {
        java.security.cert.CRLReason jdk = entry.getRevocationReason();
        if (jdk == null) {
            return RevocationReason.UNSPECIFIED;
        }
        return switch (jdk) {
            case UNSPECIFIED -> RevocationReason.UNSPECIFIED;
            case KEY_COMPROMISE -> RevocationReason.KEY_COMPROMISE;
            case CA_COMPROMISE -> RevocationReason.CA_COMPROMISE;
            case AFFILIATION_CHANGED -> RevocationReason.AFFILIATION_CHANGED;
            case SUPERSEDED -> RevocationReason.SUPERSEDED;
            case CESSATION_OF_OPERATION -> RevocationReason.CESSATION_OF_OPERATION;
            case CERTIFICATE_HOLD -> RevocationReason.CERTIFICATE_HOLD;
            case REMOVE_FROM_CRL -> RevocationReason.REMOVE_FROM_CRL;
            case PRIVILEGE_WITHDRAWN -> RevocationReason.PRIVILEGE_WITHDRAWN;
            case AA_COMPROMISE -> RevocationReason.AA_COMPROMISE;
            case UNUSED -> RevocationReason.UNSPECIFIED;
        };
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
