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
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Conservative issuance checks against the known identity chain. This does not
 * establish trust, discover missing issuers, or perform revocation validation.
 * It never invokes the identity's signing operation.
 */
final class ProfileIssuerValidation {
    private ProfileIssuerValidation() {}

    static void validate(PkiIdentity issuer, X500Principal childSubject,
                         boolean childIsCa, Integer childPathLength,
                         Instant notBefore, Instant notAfter, ExtendedKeyUsage childPurpose) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(childSubject, "childSubject");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        require(notAfter.isAfter(notBefore), "Profile validity must have notAfter after notBefore");
        require(childIsCa ? childPathLength != null && childPathLength >= 0 : childPathLength == null,
                "Profile intermediate requires a finite nonnegative path length; TLS must not set one");
        require(childIsCa ? childPurpose == null : childPurpose != null,
                "Profile CA and TLS purpose settings conflict");

        BigInteger below = childIsCa
                && !childSubject.equals(issuer.getCertificate().getSubjectX500Principal())
                ? BigInteger.ONE : BigInteger.ZERO;
        for (int index = 0; index < issuer.getChain().size(); index++) {
            X509Certificate certificate = issuer.getChain().get(index);
            String context = "Issuer at chain index " + index + " ("
                    + certificate.getSubjectX500Principal().getName() + "): ";
            require(!certificate.getSubjectX500Principal().getName().isEmpty(),
                    context + "CA subject must not be empty");
            require(!notBefore.isBefore(certificate.getNotBefore().toInstant())
                            && !notAfter.isAfter(certificate.getNotAfter().toInstant()),
                    context + "requested validity must be within the issuer validity interval");
            try {
                Extensions extensions = new X509CertificateHolder(certificate.getEncoded()).getExtensions();
                Extension basicExtension = extension(extensions, Extension.basicConstraints);
                require(basicExtension != null && basicExtension.isCritical(),
                        context + "critical CA BasicConstraints is required");
                BasicConstraints constraints = BasicConstraints.getInstance(basicExtension.getParsedValue());
                require(constraints.isCA(), context + "BasicConstraints must assert CA:true");

                Extension usageExtension = extension(extensions, Extension.keyUsage);
                require(usageExtension != null && org.bouncycastle.asn1.x509.KeyUsage
                                .getInstance(usageExtension.getParsedValue())
                                .hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),
                        context + "KeyUsage must explicitly permit keyCertSign");

                rejectUnsupportedConstraints(extensions, context);
                validatePurpose(extensions, childIsCa, childPurpose, context);
                for (ASN1ObjectIdentifier oid : extensions.getCriticalExtensionOIDs()) {
                    require(oid.equals(Extension.basicConstraints) || oid.equals(Extension.keyUsage)
                                    || (!childIsCa && oid.equals(Extension.extendedKeyUsage)),
                            context + "unsupported critical extension " + oid.getId());
                }

                BigInteger limit = constraints.getPathLenConstraint();
                if (limit != null) {
                    require(limit.signum() >= 0 && below.compareTo(limit) <= 0,
                            context + "CA path length constraint is exhausted");
                    if (childIsCa) {
                        require(BigInteger.valueOf(childPathLength).compareTo(limit.subtract(below)) <= 0,
                                context + "child path length exceeds the remaining issuer allowance");
                    }
                }
            } catch (CertificateEncodingException | IOException | IllegalArgumentException e) {
                throw new IllegalStateException(context + "cannot read issuer certificate extensions", e);
            }
            // Self-issued rollover certificates do not consume a path level.
            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                below = below.add(BigInteger.ONE);
            }
        }
    }

    private static Extension extension(Extensions extensions, ASN1ObjectIdentifier oid) {
        return extensions == null ? null : extensions.getExtension(oid);
    }

    private static void rejectUnsupportedConstraints(Extensions extensions, String context) {
        rejectExtension(extensions, Extension.nameConstraints, "nameConstraints", context);
        rejectExtension(extensions, Extension.policyConstraints, "policyConstraints", context);
        rejectExtension(extensions, Extension.policyMappings, "policyMappings", context);
        rejectExtension(extensions, Extension.inhibitAnyPolicy, "inhibitAnyPolicy", context);
    }

    private static void rejectExtension(Extensions extensions, ASN1ObjectIdentifier oid,
                                        String name, String context) {
        require(extension(extensions, oid) == null,
                context + "unsupported issuer constraint " + name + " (" + oid.getId() + ")");
    }

    private static void validatePurpose(Extensions extensions, boolean childIsCa,
                                        ExtendedKeyUsage childPurpose, String context) {
        Extension extension = extension(extensions, Extension.extendedKeyUsage);
        if (extension == null) return;
        require(!childIsCa, context + "CA issuance under issuer ExtendedKeyUsage is unsupported");
        org.bouncycastle.asn1.x509.ExtendedKeyUsage purposes =
                org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extension.getParsedValue());
        require(purposes.hasKeyPurposeId(childPurpose.purposeId())
                        || purposes.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage),
                context + "ExtendedKeyUsage does not permit " + childPurpose);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
