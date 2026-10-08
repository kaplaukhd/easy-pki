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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/** Immutable, per-build extension snapshot. Applying a profile never mutates builder defaults. */
record ProfileConfiguration(boolean ca, Integer pathLength, Set<KeyUsage> keyUsages,
                            Set<ExtendedKeyUsage> extendedKeyUsages, GeneralNames names,
                            boolean criticalSan) {
    ProfileConfiguration {
        EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
        usages.addAll(keyUsages);
        keyUsages = Collections.unmodifiableSet(usages);
        EnumSet<ExtendedKeyUsage> purposes = EnumSet.noneOf(ExtendedKeyUsage.class);
        purposes.addAll(extendedKeyUsages);
        extendedKeyUsages = Collections.unmodifiableSet(purposes);
    }

    static ProfileConfiguration resolve(CertificateProfile profile, boolean selfSigned,
            X500Name subject, PublicKey publicKey, boolean caConfigured, boolean ca,
            Integer pathLength, Set<KeyUsage> keyUsages, Set<ExtendedKeyUsage> purposes,
            SanBuilder san) {
        GeneralNames names = san == null || san.isEmpty() ? null : new GeneralNames(san.toGeneralNames());
        if (profile == null) return new ProfileConfiguration(ca, pathLength, keyUsages, purposes, names, false);
        if (profile == CertificateProfile.ROOT_CA && !selfSigned) {
            throw invalid(profile, "Root CA must be self-signed");
        }
        if (profile == CertificateProfile.INTERMEDIATE_CA && selfSigned) {
            throw invalid(profile, "Intermediate CA requires an issuing identity");
        }
        String keyOid = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())
                .getAlgorithm().getAlgorithm().getId();
        // rsaEncryption, RSASSA-PSS, id-ecPublicKey and Ed25519 are the
        // signing key families covered by these profiles. XDH is not signing.
        if (!Set.of("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10",
                "1.2.840.10045.2.1", "1.3.101.112").contains(keyOid)) {
            throw invalid(profile, "unsupported signing subject key algorithm " + keyOid);
        }
        if (caConfigured && ca != profile.isCa()) {
            throw invalid(profile, "conflicting CA flag");
        }
        if (san != null) san.requireAsciiValues();
        boolean emptySubject = subject.getRDNs().length == 0;
        if (selfSigned && emptySubject) {
            throw invalid(profile, "self-signed certificate requires a nonempty subject and issuer DN");
        }
        EnumSet<KeyUsage> effectiveUsage = EnumSet.noneOf(KeyUsage.class);
        effectiveUsage.addAll(keyUsages);
        EnumSet<ExtendedKeyUsage> effectivePurposes = EnumSet.noneOf(ExtendedKeyUsage.class);
        effectivePurposes.addAll(purposes);
        if (profile.isCa()) {
            TlsProfileNames.validateClient(names);
            if (emptySubject) throw invalid(profile, "CA subject must not be empty");
            effectiveUsage.add(KeyUsage.KEY_CERT_SIGN);
            effectiveUsage.add(KeyUsage.CRL_SIGN);
            if (!effectiveUsage.equals(EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN))) {
                throw invalid(profile, "CA KeyUsage permits only keyCertSign and cRLSign");
            }
            if (!effectivePurposes.isEmpty()) throw invalid(profile, "CA profile does not permit ExtendedKeyUsage");
            Integer effectivePath = pathLength != null ? pathLength
                    : profile == CertificateProfile.INTERMEDIATE_CA ? Integer.valueOf(0) : null;
            return new ProfileConfiguration(true, effectivePath, effectiveUsage, effectivePurposes, names, false);
        }
        if (pathLength != null) throw invalid(profile, "TLS certificate must not have a CA path length");
        effectiveUsage.add(KeyUsage.DIGITAL_SIGNATURE);
        EnumSet<KeyUsage> allowed = EnumSet.of(KeyUsage.DIGITAL_SIGNATURE);
        if (profile == CertificateProfile.TLS_SERVER && "1.2.840.113549.1.1.1".equals(keyOid)) {
            allowed.add(KeyUsage.KEY_ENCIPHERMENT);
        }
        if (!allowed.containsAll(effectiveUsage)) {
            throw invalid(profile, "conflicting TLS KeyUsage; digitalSignature is required, RSA server keyEncipherment is optional");
        }
        ExtendedKeyUsage purpose = profile == CertificateProfile.TLS_SERVER
                ? ExtendedKeyUsage.TLS_SERVER : ExtendedKeyUsage.TLS_CLIENT;
        effectivePurposes.add(purpose);
        if (!effectivePurposes.equals(EnumSet.of(purpose))) {
            throw invalid(profile, "conflicting ExtendedKeyUsage; expected only " + purpose);
        }
        if (profile == CertificateProfile.TLS_SERVER) TlsProfileNames.validateServer(names);
        else {
            TlsProfileNames.validateClient(names);
            if (emptySubject && !TlsProfileNames.hasNames(names)) {
                throw invalid(profile, "TLS client requires an explicit subject or SAN identity");
            }
        }
        return new ProfileConfiguration(false, null, effectiveUsage, effectivePurposes, names, emptySubject);
    }

    static Instant encodedTime(Instant value) {
        Instant seconds = value.truncatedTo(ChronoUnit.SECONDS);
        if (seconds.isBefore(Instant.parse("1950-01-01T00:00:00Z"))
                || seconds.isAfter(Instant.parse("9999-12-31T23:59:59Z"))) {
            throw new IllegalStateException("Profile validity must be representable in X.509 years 1950 through 9999");
        }
        return seconds;
    }

    private static IllegalStateException invalid(CertificateProfile profile, String message) {
        return new IllegalStateException(profile + " profile: " + message);
    }
}
