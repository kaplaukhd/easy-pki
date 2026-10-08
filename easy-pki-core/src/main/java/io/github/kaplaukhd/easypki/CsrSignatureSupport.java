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
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** Verifies CSR proofs through host JCA providers without global provider registration. */
final class CsrSignatureSupport {
    private CsrSignatureSupport() {}

    static boolean verify(PublicKey key, AlgorithmIdentifier algorithm, byte[] content, byte[] signature) {
        try {
            String oid = algorithm.getAlgorithm().getId();
            String name = signatureName(oid);
            if (name == null) return false;
            Signature verifier = Signature.getInstance(name);
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm.getAlgorithm())) {
                verifier.setParameter(pssParameters(algorithm.getParameters()));
            } else if (name.endsWith("withRSA")) {
                requireAbsentOrNull(algorithm);
            } else if (algorithm.getParameters() != null) {
                return false;
            }
            verifier.initVerify(key);
            verifier.update(content);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IOException | IllegalArgumentException | ClassCastException | ArithmeticException e) {
            return false;
        }
    }

    private static String signatureName(String oid) {
        return switch (oid) {
            case "1.2.840.113549.1.1.5" -> "SHA1withRSA";
            case "1.2.840.113549.1.1.14" -> "SHA224withRSA";
            case "1.2.840.113549.1.1.11" -> "SHA256withRSA";
            case "1.2.840.113549.1.1.12" -> "SHA384withRSA";
            case "1.2.840.113549.1.1.13" -> "SHA512withRSA";
            case "1.2.840.113549.1.1.10" -> "RSASSA-PSS";
            case "1.2.840.10045.4.1" -> "SHA1withECDSA";
            case "1.2.840.10045.4.3.1" -> "SHA224withECDSA";
            case "1.2.840.10045.4.3.2" -> "SHA256withECDSA";
            case "1.2.840.10045.4.3.3" -> "SHA384withECDSA";
            case "1.2.840.10045.4.3.4" -> "SHA512withECDSA";
            case "1.3.101.112" -> "Ed25519";
            default -> null;
        };
    }

    private static PSSParameterSpec pssParameters(ASN1Encodable encoded) throws IOException {
        if (encoded == null) throw new IllegalArgumentException("RSA-PSS requires encoded parameters");
        ASN1Sequence sequence = ASN1Sequence.getInstance(encoded);
        int previousTag = -1;
        for (ASN1Encodable entry : sequence) {
            ASN1TaggedObject field = ASN1TaggedObject.getInstance(entry);
            if (!field.hasContextTag() || !field.isExplicit() || field.getTagNo() <= previousTag || field.getTagNo() > 3) {
                throw new IllegalArgumentException("Invalid RSA-PSS parameter fields");
            }
            previousTag = field.getTagNo();
        }
        RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(sequence);
        if (!java.util.Arrays.equals(sequence.getEncoded(ASN1Encoding.DER), parameters.getEncoded(ASN1Encoding.DER))) {
            throw new IllegalArgumentException("RSA-PSS parameters must be canonical DER");
        }
        AlgorithmIdentifier hash = CsrRequest.algorithmIdentifier(parameters.getHashAlgorithm());
        requireAbsentOrNull(hash);
        AlgorithmIdentifier mask = CsrRequest.algorithmIdentifier(parameters.getMaskGenAlgorithm());
        if (!PKCSObjectIdentifiers.id_mgf1.equals(mask.getAlgorithm()) || mask.getParameters() == null) {
            throw new IllegalArgumentException("RSA-PSS requires MGF1 with an explicit digest");
        }
        AlgorithmIdentifier mgfHash = CsrRequest.algorithmIdentifier(mask.getParameters());
        requireAbsentOrNull(mgfHash);
        int saltLength = parameters.getSaltLength().intValueExact();
        int trailer = parameters.getTrailerField().intValueExact();
        if (saltLength < 0 || trailer != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new IllegalArgumentException("Invalid RSA-PSS salt length or trailer field");
        }
        return new PSSParameterSpec(digestName(hash), "MGF1", new MGF1ParameterSpec(digestName(mgfHash)), saltLength, trailer);
    }

    private static void requireAbsentOrNull(AlgorithmIdentifier algorithm) {
        if (algorithm.getParameters() != null && !(algorithm.getParameters().toASN1Primitive() instanceof ASN1Null)) {
            throw new IllegalArgumentException("Unexpected algorithm parameters");
        }
    }

    private static String digestName(AlgorithmIdentifier algorithm) {
        return switch (algorithm.getAlgorithm().getId()) {
            case "1.3.14.3.2.26" -> "SHA-1";
            case "2.16.840.1.101.3.4.2.4" -> "SHA-224";
            case "2.16.840.1.101.3.4.2.1" -> "SHA-256";
            case "2.16.840.1.101.3.4.2.2" -> "SHA-384";
            case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
            case "2.16.840.1.101.3.4.2.5" -> "SHA-512/224";
            case "2.16.840.1.101.3.4.2.6" -> "SHA-512/256";
            default -> throw new IllegalArgumentException("Unsupported RSA-PSS digest");
        };
    }
}
