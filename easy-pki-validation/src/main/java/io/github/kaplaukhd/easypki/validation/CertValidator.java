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

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import io.github.kaplaukhd.easypki.PkiCertInfo;

/**
 * Fluent certificate validator.
 *
 * <p>Validates a supplied, ordered chain with the JCA PKIX validator against
 * explicitly configured {@linkplain #trustAnchors(X509Certificate...) trust anchors}.
 * Supplying a certificate in the chain never establishes trust. Use
 * {@link ChainBuilder} to select a path from an unordered pool of intermediates.
 *
 * <p>A terminal configured anchor is excluded from the internal PKIX path:
 * its own validity, self-signature and certificate extensions are not checked.
 * Revocation remains opt-in and is performed only after path validation succeeds.
 *
 * <h2>Simple chain check</h2>
 * <pre>{@code
 * ValidationResult r = CertValidator.of(leaf).chain(intermediate, root)
 *     .trustAnchors(root).validate();
 * }</pre>
 *
 * <h2>With CRL-based revocation</h2>
 * <pre>{@code
 * // Static CRLs (off-line):
 * CertValidator.of(leaf).chain(intermediate, root).trustAnchors(root)
 *     .crl(fetchedCrl).validate();
 *
 * // HTTP auto-fetch from each cert's CDP extension, with a 30-minute cache:
 * CertValidator.of(leaf)
 *     .chain(intermediate, root)
 *     .trustAnchors(root)
 *     .crl(c -> c.autoFetch()
 *                .cache(Duration.ofMinutes(30))
 *                .timeout(Duration.ofSeconds(10))
 *                .proxy("http://proxy.corp:3128"))
 *     .validate();
 * }</pre>
 */
public final class CertValidator {

    private final X509Certificate certificate;
    private final List<X509Certificate> chain = new ArrayList<>();
    private final Set<X509Certificate> trustAnchors = new HashSet<>();
    private CrlConfig crlConfig;
    private HttpCrlFetcher httpCrlFetcher;
    private OcspConfig ocspConfig;
    private OcspClient ocspClient;
    private OcspSettings ocspSettings;
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
     * Supplies intermediates and (optionally) the trust anchor in issuer order.
     * Trust must be configured separately via {@link #trustAnchors(X509Certificate...)}.
     * The supplied chain is neither reordered nor truncated at an earlier anchor.
     * Multiple calls accumulate.
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
     * Registers explicit trust anchors. The last supplied certificate must be
     * an anchor or be issued by one. An anchor need not be self-signed.
     * A directly trusted target is also accepted. Multiple calls accumulate;
     * null anchors are rejected before any are added.
     */
    public CertValidator trustAnchors(X509Certificate... anchors) {
        Objects.requireNonNull(anchors, "anchors");
        return trustAnchors(Arrays.asList(anchors));
    }

    /** Overload that accepts a collection. */
    public CertValidator trustAnchors(Collection<X509Certificate> anchors) {
        Objects.requireNonNull(anchors, "anchors");
        this.trustAnchors.addAll(List.copyOf(anchors));
        return this;
    }

    /**
     * Sets the instant used for certificate validity, CRL validity and OCSP
     * response freshness. Default is the instant at the start of validation.
     * A current online OCSP answer may be too new for a historical instant;
     * this method does not retrieve archived revocation evidence.
     */
    public CertValidator at(Instant evaluationTime) {
        this.evaluationTime = Objects.requireNonNull(evaluationTime, "evaluationTime");
        return this;
    }

    /**
     * Convenience: enables CRL revocation checking with the given static CRLs.
     * Equivalent to {@code crl(c -> c.add(crls))}.
     */
    public CertValidator crl(X509CRL... crls) {
        Objects.requireNonNull(crls, "crls");
        ensureCrlConfig().add(crls);
        return this;
    }

    /** List overload of {@link #crl(X509CRL...)}. */
    public CertValidator crl(List<X509CRL> crls) {
        Objects.requireNonNull(crls, "crls");
        ensureCrlConfig().add(crls);
        return this;
    }

    /**
     * Configures CRL revocation checking. Enable auto-fetch, set cache TTL,
     * HTTP timeout or proxy via {@link CrlConfig}.
     */
    public CertValidator crl(Consumer<CrlConfig> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        configurer.accept(ensureCrlConfig());
        return this;
    }

    private CrlConfig ensureCrlConfig() {
        if (crlConfig == null) {
            crlConfig = new CrlConfig();
        }
        return crlConfig;
    }

    /**
     * Enables OCSP-based revocation checking with defaults (URL taken from
     * each cert's AIA extension, 10-second timeout, nonce enabled).
     */
    public CertValidator ocsp() {
        ensureOcspConfig();
        return this;
    }

    /** Configures OCSP-based revocation checking. */
    public CertValidator ocsp(Consumer<OcspConfig> configurer) {
        Objects.requireNonNull(configurer, "configurer");
        configurer.accept(ensureOcspConfig());
        return this;
    }

    private OcspConfig ensureOcspConfig() {
        if (ocspConfig == null) {
            ocspConfig = new OcspConfig();
        }
        return ocspConfig;
    }

    /**
     * Convenience that enables OCSP with CRL auto-fetch as a fallback. The
     * resulting behaviour is equivalent to
     * {@code .ocsp().crl(c -> c.autoFetch())}. Further refinements (explicit
     * URLs, timeouts, proxies) can be added via subsequent {@link #ocsp(Consumer)}
     * or {@link #crl(Consumer)} calls.
     */
    public CertValidator ocspWithCrlFallback() {
        ensureOcspConfig();
        ensureCrlConfig().autoFetch();
        return this;
    }

    /**
     * Performs PKIX path validation and then any configured revocation checks.
     * Missing explicit trust is reported as {@link ValidationError.Code#UNTRUSTED_ROOT}.
     * PKIX algorithm constraints follow the host JCA provider and security policy.
     * Revocation considers every certificate below the selected anchor,
     * whether or not that anchor was included in {@code chain(...)}. Recovered
     * source failures appear in {@link ValidationResult#getWarnings()}.
     */
    public ValidationResult validate() {
        Instant now = (evaluationTime != null) ? evaluationTime : Instant.now();

        List<X509Certificate> path = new ArrayList<>(1 + chain.size());
        path.add(certificate);
        path.addAll(chain);

        List<ValidationError> errors = new ArrayList<>();
        boolean expired = false;
        boolean notYetValid = false;

        // Retain per-certificate date diagnostics, but exclude an explicit anchor
        // just as PKIX does. The public path retains the caller's supplied chain.
        List<X509Certificate> certificatesToValidate = certificatesToValidate(path);
        for (X509Certificate c : certificatesToValidate) {
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

        // Preserve a precise diagnostic when PKIX reports a generic failure
        // to reach an anchor for a supplied chain with mismatched issuer names.
        for (int i = 0; i < path.size() - 1; i++) {
            X509Certificate child = path.get(i);
            X509Certificate parent = path.get(i + 1);
            if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
                errors.add(new ValidationError(ValidationError.Code.ISSUER_MISMATCH,
                        "Issuer of '" + subject(child) + "' does not match subject of '"
                                + subject(parent) + "'"));
            }
        }

        boolean trusted = determineTrust(path, errors);
        X509Certificate selectedAnchor = trustAnchors.contains(path.get(path.size() - 1))
                ? path.get(path.size() - 1) : null;
        if (trusted && !certificatesToValidate.isEmpty()) {
            selectedAnchor = validatePkix(path, certificatesToValidate, now, errors);
        }

        ValidationResult.Builder builder = ValidationResult.builder()
                .validationPath(Collections.unmodifiableList(path))
                .expired(expired)
                .notYetValid(notYetValid)
                .trusted(trusted);

        if (errors.isEmpty() && (ocspConfig != null || crlConfig != null)) {
            List<X509Certificate> revocationPath = new ArrayList<>(certificatesToValidate);
            revocationPath.add(Objects.requireNonNull(selectedAnchor, "PKIX trust anchor"));
            checkRevocation(revocationPath, errors, now, builder);
        }

        builder.errors(Collections.unmodifiableList(errors));
        return builder.build();
    }

    private List<X509Certificate> certificatesToValidate(List<X509Certificate> path) {
        if (trustAnchors.contains(path.get(path.size() - 1))) {
            return path.subList(0, path.size() - 1);
        }
        return path;
    }

    private X509Certificate validatePkix(List<X509Certificate> suppliedPath,
                                        List<X509Certificate> certificatesToValidate,
                                        Instant now, List<ValidationError> errors) {
        X509Certificate last = suppliedPath.get(suppliedPath.size() - 1);
        // If the caller included an anchor, bind validation to that exact one.
        // Otherwise PKIX may select an issuer from the configured anchor set.
        Collection<X509Certificate> anchors = trustAnchors.contains(last)
                ? List.of(last) : trustAnchors;
        Set<TrustAnchor> pkixAnchors = new HashSet<>();
        for (X509Certificate anchor : anchors) {
            pkixAnchors.add(new TrustAnchor(anchor, null));
        }
        try {
            PKIXParameters parameters = new PKIXParameters(pkixAnchors);
            parameters.setDate(Date.from(now));
            // Revocation is handled by the library's existing opt-in pipeline.
            parameters.setRevocationEnabled(false);
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                    CertPathValidator.getInstance("PKIX").validate(
                    CertificateFactory.getInstance("X.509").generateCertPath(certificatesToValidate),
                    parameters);
            return result.getTrustAnchor().getTrustedCert();
        } catch (CertPathValidatorException e) {
            ValidationError.Code code = pkixErrorCode(e);
            // Date failures have already been reported individually above.
            if ((code == ValidationError.Code.EXPIRED || code == ValidationError.Code.NOT_YET_VALID)
                    && errors.stream().anyMatch(error -> error.code() == code)) {
                return null;
            }
            String location = e.getIndex() >= 0 && e.getIndex() < certificatesToValidate.size()
                    ? "Certificate '" + subject(certificatesToValidate.get(e.getIndex())) + "': "
                    : "Certificate path: ";
            errors.add(new ValidationError(code, location + e.getMessage()));
        } catch (GeneralSecurityException e) {
            errors.add(new ValidationError(ValidationError.Code.PKIX_VALIDATION_FAILED,
                    "Unable to validate the PKIX path: " + e.getMessage()));
        }
        return null;
    }

    private static ValidationError.Code pkixErrorCode(CertPathValidatorException exception) {
        CertPathValidatorException.Reason reason = exception.getReason();
        if (reason instanceof CertPathValidatorException.BasicReason basic) {
            return switch (basic) {
                case EXPIRED -> ValidationError.Code.EXPIRED;
                case NOT_YET_VALID -> ValidationError.Code.NOT_YET_VALID;
                case INVALID_SIGNATURE -> ValidationError.Code.BROKEN_SIGNATURE;
                case ALGORITHM_CONSTRAINED -> ValidationError.Code.ALGORITHM_CONSTRAINED;
                case REVOKED -> ValidationError.Code.REVOKED;
                case UNDETERMINED_REVOCATION_STATUS -> ValidationError.Code.REVOCATION_UNKNOWN;
                case UNSPECIFIED -> ValidationError.Code.PKIX_VALIDATION_FAILED;
            };
        }
        if (reason instanceof PKIXReason pkix) {
            return switch (pkix) {
                case NAME_CHAINING -> ValidationError.Code.ISSUER_MISMATCH;
                case INVALID_KEY_USAGE -> ValidationError.Code.INVALID_KEY_USAGE;
                case INVALID_POLICY -> ValidationError.Code.INVALID_POLICY;
                case NO_TRUST_ANCHOR -> ValidationError.Code.UNTRUSTED_ROOT;
                case UNRECOGNIZED_CRIT_EXT -> ValidationError.Code.UNRECOGNIZED_CRITICAL_EXTENSION;
                case NOT_CA_CERT -> ValidationError.Code.NOT_A_CA;
                case PATH_TOO_LONG -> ValidationError.Code.PATH_TOO_LONG;
                case INVALID_NAME -> ValidationError.Code.INVALID_NAME;
            };
        }
        return ValidationError.Code.PKIX_VALIDATION_FAILED;
    }

    private void checkRevocation(List<X509Certificate> path,
                                 List<ValidationError> errors,
                                 Instant now,
                                 ValidationResult.Builder builder) {
        List<ValidationError> warnings = new ArrayList<>();
        for (int i = 0; i < path.size() - 1; i++) {
            X509Certificate subject = path.get(i);
            X509Certificate issuer = path.get(i + 1);
            List<ValidationError> attemptFailures = new ArrayList<>();
            boolean determined = false;

            // --- OCSP (preferred when configured and applicable) ---
            if (ocspConfig != null) {
                URI url = resolveOcspUrl(subject, i == 0);
                if (url != null) {
                    OcspClient.Outcome outcome = ocspClient().query(url, subject, issuer, now);
                    switch (outcome.kind()) {
                        case GOOD -> determined = true;
                        case REVOKED -> {
                            errors.add(new ValidationError(
                                    ValidationError.Code.REVOKED,
                                    "Certificate '" + subject(subject) + "' was revoked on "
                                            + outcome.revokedAt() + " (" + outcome.reason() + ")"));
                            if (!builder.isRevoked()) {
                                builder.revoked(outcome.reason(), outcome.revokedAt());
                            }
                            determined = true;
                        }
                        case UNKNOWN_STATUS -> attemptFailures.add(new ValidationError(
                                ValidationError.Code.REVOCATION_UNKNOWN,
                                "OCSP responder reports unknown status for '"
                                        + subject(subject) + "' at " + url));
                        case UNAVAILABLE -> attemptFailures.add(new ValidationError(
                                ValidationError.Code.OCSP_UNAVAILABLE,
                                "OCSP check failed for '" + subject(subject) + "' at " + url + ": "
                                        + outcome.detail()));
                    }
                }
                // No URL available for this cert — silently fall through to CRL.
            }

            if (determined) {
                warnings.addAll(attemptFailures);
                continue;
            }

            // --- CRL fallback ---
            if (crlConfig != null) {
                X509CRL applicable = findApplicableCrl(subject, issuer, now, attemptFailures, warnings);
                if (applicable != null) {
                    X509CRLEntry entry = applicable.getRevokedCertificate(subject);
                    if (entry == null) {
                        determined = true;
                    } else {
                        RevocationReason reason = extractReason(entry);
                        Instant revokedAt = entry.getRevocationDate().toInstant();
                        errors.add(new ValidationError(
                                ValidationError.Code.REVOKED,
                                "Certificate '" + subject(subject) + "' was revoked on "
                                        + revokedAt + " (" + reason + ")"));
                        if (!builder.isRevoked()) {
                            builder.revoked(reason, revokedAt);
                        }
                        determined = true;
                    }
                }
            }

            if (determined) {
                warnings.addAll(attemptFailures);
            } else {
                ValidationError unknown = new ValidationError(ValidationError.Code.REVOCATION_UNKNOWN,
                        "Could not determine revocation status of '" + subject(subject) + "'");
                if (i == 0 || !attemptFailures.isEmpty()) {
                    // Recovery is local to this certificate. A successful check
                    // of a different certificate cannot erase these failures.
                    errors.addAll(attemptFailures);
                    errors.add(unknown);
                } else {
                    // Preserve the existing intermediate-with-no-source policy,
                    // but expose that its revocation status was not established.
                    warnings.add(unknown);
                }
            }
        }
        builder.warnings(warnings);
    }

    private URI resolveOcspUrl(X509Certificate subject, boolean isSubjectLeaf) {
        // URL override applies only to the subject (leaf) being validated.
        // Intermediate certs must use their own AIA OCSP URL (or be skipped).
        if (isSubjectLeaf && ocspConfig.url() != null) {
            return ocspConfig.url();
        }
        for (String raw : PkiCertInfo.of(subject).getOcspUrls()) {
            try {
                URI uri = URI.create(raw);
                if (uri.getScheme() != null
                        && (uri.getScheme().equalsIgnoreCase("http")
                                || uri.getScheme().equalsIgnoreCase("https"))) {
                    return uri;
                }
            } catch (IllegalArgumentException ignored) {
                // try next
            }
        }
        return null;
    }

    private OcspClient ocspClient() {
        OcspSettings settings = new OcspSettings(ocspConfig.timeout(), ocspConfig.proxy(),
                ocspConfig.isNonceEnabled(), ocspConfig.clockSkew(), ocspConfig.maxResponseAge());
        if (ocspClient == null || !settings.equals(ocspSettings)) {
            ocspClient = new OcspClient(
                    settings.timeout(), settings.proxy(), settings.nonceEnabled(),
                    settings.clockSkew(), settings.maxResponseAge());
            ocspSettings = settings;
        }
        return ocspClient;
    }

    private record OcspSettings(Duration timeout, URI proxy, boolean nonceEnabled,
                                Duration clockSkew, Duration maxResponseAge) {}

    private X509CRL findApplicableCrl(X509Certificate subject,
                                     X509Certificate issuer,
                                     Instant now,
                                     List<ValidationError> errors,
                                     List<ValidationError> warnings) {
        // 1) Static CRLs supplied by the user.
        for (X509CRL crl : crlConfig.staticCrls()) {
            if (matchesAndValid(crl, subject, issuer, now, errors, "static CRL", true)) {
                return crl;
            }
        }
        // 2) HTTP auto-fetch from the cert's own CDP URLs, with caching.
        if (crlConfig.isAutoFetch()) {
            for (String rawUrl : PkiCertInfo.of(subject).getCrlUrls()) {
                URI uri;
                try {
                    uri = URI.create(rawUrl);
                } catch (IllegalArgumentException e) {
                    warnings.add(crlFailure(subject, rawUrl, "Skipped invalid distribution point URI"));
                    continue;
                }
                // Only http/https; other schemes (e.g. ldap://) are out of scope.
                String scheme = uri.getScheme();
                if (scheme == null
                        || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                    warnings.add(crlFailure(subject, rawUrl, "Skipped unsupported distribution point scheme"));
                    continue;
                }
                Optional<X509CRL> fetched = httpFetcher().fetch(uri);
                if (fetched.isEmpty()) {
                    errors.add(new ValidationError(
                            ValidationError.Code.CRL_UNAVAILABLE,
                            "Failed to fetch CRL for '" + subject(subject) + "' from " + rawUrl));
                    continue;
                }
                X509CRL crl = fetched.get();
                if (matchesAndValid(crl, subject, issuer, now, errors, rawUrl, false)) {
                    return crl;
                }
            }
        }
        return null;
    }

    private boolean matchesAndValid(X509CRL crl,
                                    X509Certificate subject,
                                    X509Certificate issuer,
                                    Instant now,
                                    List<ValidationError> errors,
                                    String source,
                                    boolean ignoreUnrelatedIssuer) {
        if (!crl.getIssuerX500Principal().equals(subject.getIssuerX500Principal())) {
            if (!ignoreUnrelatedIssuer) {
                errors.add(crlFailure(subject, source, "CRL issuer does not match the certificate issuer"));
            }
            return false;
        }
        if (crl.getThisUpdate() == null || crl.getThisUpdate().toInstant().isAfter(now)) {
            errors.add(crlFailure(subject, source, "CRL thisUpdate is missing or in the future"));
            return false;
        }
        if (crl.getNextUpdate() != null && crl.getNextUpdate().toInstant().isBefore(now)) {
            errors.add(crlFailure(subject, source, "CRL is expired (nextUpdate="
                    + crl.getNextUpdate().toInstant() + ")"));
            return false;
        }
        try {
            crl.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            errors.add(crlFailure(subject, source, "CRL signature does not verify: " + e.getMessage()));
            return false;
        }
        return true;
    }

    private static ValidationError crlFailure(X509Certificate subject, String source, String detail) {
        return new ValidationError(ValidationError.Code.CRL_UNAVAILABLE,
                "CRL check for '" + subject(subject) + "' from " + source + ": " + detail);
    }

    private HttpCrlFetcher httpFetcher() {
        if (httpCrlFetcher == null) {
            httpCrlFetcher = new HttpCrlFetcher(
                    crlConfig.httpTimeout(),
                    crlConfig.proxy(),
                    crlConfig.cacheTtl());
        }
        return httpCrlFetcher;
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
        X509Certificate last = path.get(path.size() - 1);
        if (trustAnchors.contains(last)) {
            return true;
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
                trustAnchors.isEmpty()
                        ? "No trust anchors configured; supply trusted certificates via trustAnchors(...)"
                        : "Chain does not terminate in a configured trust anchor (last cert: '"
                                + subject(last) + "')"));
        return false;
    }

    private static String subject(X509Certificate c) {
        return c.getSubjectX500Principal().getName();
    }
}
