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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * The outcome of a {@link CertValidator#validate() validation}.
 *
 * <p>Typical use:
 * <pre>{@code
 * ValidationResult result = CertValidator.of(cert)
 *     .chain(intermediate, root)
 *     .trustAnchors(root)
 *     .validate();
 *
 * if (!result.isValid()) {
 *     for (ValidationError err : result.getErrors()) {
 *         log.warn("{}: {}", err.code(), err.message());
 *     }
 * }
 * }</pre>
 */
public final class ValidationResult {

    private final boolean valid;
    private final boolean expired;
    private final boolean notYetValid;
    private final boolean trusted;
    private final boolean revoked;
    private final RevocationReason revocationReason;
    private final Instant revocationTime;
    private final List<X509Certificate> validationPath;
    private final List<ValidationError> errors;

    private ValidationResult(Builder b) {
        this.expired = b.expired;
        this.notYetValid = b.notYetValid;
        this.trusted = b.trusted;
        this.revoked = b.revoked;
        this.revocationReason = b.revocationReason;
        this.revocationTime = b.revocationTime;
        this.validationPath = List.copyOf(b.validationPath);
        this.errors = List.copyOf(b.errors);
        this.valid = errors.isEmpty();
    }

    /** {@code true} if validation found no errors. */
    public boolean isValid() {
        return valid;
    }

    /** {@code true} if a non-anchor certificate in the supplied path is already expired. */
    public boolean isExpired() {
        return expired;
    }

    /** {@code true} if a non-anchor certificate in the supplied path is not yet valid. */
    public boolean isNotYetValid() {
        return notYetValid;
    }

    /**
     * {@code true} if the terminal certificate is an explicitly configured anchor
     * or its signature links it to one. This alone does not establish a valid
     * PKIX path: use {@link #isValid()} to decide whether validation succeeded.
     */
    public boolean isTrusted() {
        return trusted;
    }

    /** {@code true} if revocation checking reported the certificate as revoked. */
    public boolean isRevoked() {
        return revoked;
    }

    /** The revocation reason, or {@code null} if the certificate is not revoked. */
    public RevocationReason getRevokeReason() {
        return revocationReason;
    }

    /** The revocation timestamp, or {@code null} if the certificate is not revoked. */
    public Instant getRevokeTime() {
        return revocationTime;
    }

    /**
     * The supplied ordered chain, with the subject (leaf) certificate first.
     * A trust anchor is included only if it was supplied in that chain; anchors
     * configured separately are not appended. An included terminal anchor is
     * retained here even though PKIX excludes it from certificate checks.
     */
    public List<X509Certificate> getValidationPath() {
        return validationPath;
    }

    /** All errors encountered. Empty if {@link #isValid()} is {@code true}. */
    public List<ValidationError> getErrors() {
        return errors;
    }

    static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        private boolean expired;
        private boolean notYetValid;
        private boolean trusted;
        private boolean revoked;
        private RevocationReason revocationReason;
        private Instant revocationTime;
        private List<X509Certificate> validationPath = List.of();
        private List<ValidationError> errors = List.of();

        Builder expired(boolean expired) {
            this.expired = expired;
            return this;
        }

        Builder notYetValid(boolean notYetValid) {
            this.notYetValid = notYetValid;
            return this;
        }

        Builder trusted(boolean trusted) {
            this.trusted = trusted;
            return this;
        }

        Builder revoked(RevocationReason reason, Instant time) {
            this.revoked = true;
            this.revocationReason = Objects.requireNonNull(reason, "reason");
            this.revocationTime = Objects.requireNonNull(time, "time");
            return this;
        }

        boolean isRevoked() {
            return revoked;
        }

        Builder validationPath(List<X509Certificate> path) {
            this.validationPath = Objects.requireNonNull(path, "path");
            return this;
        }

        Builder errors(List<ValidationError> errors) {
            this.errors = Objects.requireNonNull(errors, "errors");
            return this;
        }

        ValidationResult build() {
            return new ValidationResult(this);
        }
    }
}
