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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.DnBuilder;
import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.SanBuilder;
import io.github.kaplaukhd.easypki.SignedCertificateBuilder;

/**
 * Fluent builder for test leaf certificates. Obtained via
 * {@link TestPki#issueCert()}.
 *
 * <p>Convenience methods cover the common test scenarios:
 * <ul>
 *   <li>{@link #expired()} — creates an already-expired certificate.</li>
 *   <li>{@link #notYetValid()} — creates a certificate with {@code notBefore}
 *       in the future.</li>
 *   <li>{@link #san(String...)} — auto-detects DNS / IP / email based on the
 *       entry shape, handy for test-server certs.</li>
 * </ul>
 *
 * <p>Call {@link #build()} for a bare {@link X509Certificate} (matching the
 * roadmap signature) or {@link #issue()} for the full {@link IssuedCert}
 * record that also exposes the generated key pair.
 */
public final class TestIssueCertBuilder {

    private final TestPki pki;

    private String subjectDn;
    private Consumer<DnBuilder> subjectConfigurer;
    private KeyPair keyPair;

    private final List<String> autoSanEntries = new ArrayList<>();
    private Consumer<SanBuilder> sanConfigurer;

    private final Set<KeyUsage> keyUsages = EnumSet.noneOf(KeyUsage.class);
    private final Set<ExtendedKeyUsage> extendedKeyUsages = EnumSet.noneOf(ExtendedKeyUsage.class);

    private Duration validFor = Duration.ofDays(30);
    private Instant validFrom;
    private Instant validUntil;

    private boolean isCa;
    private Integer pathLength;

    TestIssueCertBuilder(TestPki pki) {
        this.pki = pki;
    }

    // ---------- subject ----------

    public TestIssueCertBuilder subject(String subjectDn) {
        this.subjectDn = Objects.requireNonNull(subjectDn, "subjectDn");
        this.subjectConfigurer = null;
        return this;
    }

    public TestIssueCertBuilder subject(Consumer<DnBuilder> configurer) {
        this.subjectConfigurer = Objects.requireNonNull(configurer, "configurer");
        this.subjectDn = null;
        return this;
    }

    // ---------- key pair ----------

    /** Overrides the key pair. Default: a fresh RSA 2048 pair per call. */
    public TestIssueCertBuilder keyPair(KeyPair keys) {
        this.keyPair = Objects.requireNonNull(keys, "keys");
        return this;
    }

    /** Convenience: generate an RSA key pair of the given size. */
    public TestIssueCertBuilder rsa(int bits) {
        this.keyPair = PkiKeys.rsa(bits);
        return this;
    }

    /** Convenience: generate an EC key pair on the given curve. */
    public TestIssueCertBuilder ec(Curve curve) {
        this.keyPair = PkiKeys.ec(curve);
        return this;
    }

    // ---------- SAN ----------

    /**
     * Adds SAN entries, auto-detecting type:
     * <ul>
     *   <li>contains {@code '@'} → e-mail;</li>
     *   <li>digits-and-dots or colons → IP address;</li>
     *   <li>otherwise → DNS name.</li>
     * </ul>
     */
    public TestIssueCertBuilder san(String... entries) {
        Objects.requireNonNull(entries, "entries");
        for (String e : entries) {
            autoSanEntries.add(Objects.requireNonNull(e, "san entry"));
        }
        return this;
    }

    /** Full SAN configuration via the core's {@link SanBuilder}. */
    public TestIssueCertBuilder san(Consumer<SanBuilder> configurer) {
        this.sanConfigurer = Objects.requireNonNull(configurer, "configurer");
        return this;
    }

    // ---------- key usages ----------

    public TestIssueCertBuilder keyUsage(KeyUsage... usages) {
        Objects.requireNonNull(usages, "usages");
        for (KeyUsage u : usages) {
            keyUsages.add(Objects.requireNonNull(u, "usage"));
        }
        return this;
    }

    public TestIssueCertBuilder extendedKeyUsage(ExtendedKeyUsage... purposes) {
        Objects.requireNonNull(purposes, "purposes");
        for (ExtendedKeyUsage p : purposes) {
            extendedKeyUsages.add(Objects.requireNonNull(p, "purpose"));
        }
        return this;
    }

    // ---------- validity ----------

    public TestIssueCertBuilder validFor(Duration duration) {
        this.validFor = Objects.requireNonNull(duration, "duration");
        this.validFrom = null;
        this.validUntil = null;
        return this;
    }

    public TestIssueCertBuilder validFrom(Instant notBefore) {
        this.validFrom = Objects.requireNonNull(notBefore, "notBefore");
        return this;
    }

    public TestIssueCertBuilder validUntil(Instant notAfter) {
        this.validUntil = Objects.requireNonNull(notAfter, "notAfter");
        return this;
    }

    /** Shortcut: certificate already expired. {@code notBefore=-60d}, {@code notAfter=-1d}. */
    public TestIssueCertBuilder expired() {
        Instant now = Instant.now();
        this.validFrom = now.minus(Duration.ofDays(60));
        this.validUntil = now.minus(Duration.ofDays(1));
        return this;
    }

    /** Shortcut: certificate not yet valid. {@code notBefore=+30d}, {@code notAfter=+60d}. */
    public TestIssueCertBuilder notYetValid() {
        Instant now = Instant.now();
        this.validFrom = now.plus(Duration.ofDays(30));
        this.validUntil = now.plus(Duration.ofDays(60));
        return this;
    }

    // ---------- CA flag ----------

    public TestIssueCertBuilder isCA(boolean ca) {
        this.isCa = ca;
        return this;
    }

    public TestIssueCertBuilder pathLength(int pathLength) {
        this.pathLength = pathLength;
        this.isCa = true;
        return this;
    }

    // ---------- build ----------

    /** Builds and signs the certificate, returning the {@link X509Certificate} only. */
    public X509Certificate build() {
        return issue().certificate();
    }

    /** Builds the certificate and returns it along with the generated key pair. */
    public IssuedCert issue() {
        if (subjectDn == null && subjectConfigurer == null) {
            throw new IllegalStateException("subject is required");
        }
        KeyPair leafKeys = (keyPair != null) ? keyPair : PkiKeys.rsa(2048);

        SignedCertificateBuilder b = PkiCertificate.signed()
                .publicKey(leafKeys.getPublic())
                .issuer(pki.getIssuerCa(), pki.getIssuerPrivateKey());

        if (subjectDn != null) {
            b.subject(subjectDn);
        } else {
            b.subject(subjectConfigurer);
        }

        if (validFrom != null) {
            b.validFrom(validFrom);
        }
        if (validUntil != null) {
            b.validUntil(validUntil);
        } else if (validFrom == null) {
            b.validFor(validFor);
        } else {
            // validFrom set but no validUntil — derive from validFor offset.
            b.validUntil(validFrom.plus(validFor));
        }

        if (!keyUsages.isEmpty()) {
            b.keyUsage(keyUsages.toArray(new KeyUsage[0]));
        }
        if (!extendedKeyUsages.isEmpty()) {
            b.extendedKeyUsage(extendedKeyUsages.toArray(new ExtendedKeyUsage[0]));
        }

        if (!autoSanEntries.isEmpty() || sanConfigurer != null) {
            b.san(s -> {
                for (String entry : autoSanEntries) {
                    applySan(s, entry);
                }
                if (sanConfigurer != null) {
                    sanConfigurer.accept(s);
                }
            });
        }

        if (pathLength != null) {
            b.pathLength(pathLength);
        } else if (isCa) {
            b.isCA(true);
        }

        return new IssuedCert(b.build(), leafKeys);
    }

    private static void applySan(SanBuilder s, String entry) {
        if (entry.contains("@")) {
            s.email(entry);
        } else if (looksLikeIp(entry)) {
            s.ip(entry);
        } else {
            s.dns(entry);
        }
    }

    private static boolean looksLikeIp(String s) {
        // IPv6 contains ':'; IPv4 is digits and dots only.
        return s.indexOf(':') >= 0 || s.matches("^[0-9.]+$");
    }
}
