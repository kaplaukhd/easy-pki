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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/** Bridges certificate encoding to the public signing contract without sharing signing state. */
final class PkiSignerSupport {
    private PkiSignerSupport() {}

    static AlgorithmIdentifier algorithmIdentifier(String algorithm) {
        return algorithmIdentifier(algorithm, null);
    }

    static AlgorithmIdentifier algorithmIdentifier(String algorithm, AlgorithmParameterSpec parameters) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (algorithm.isBlank()) throw new IllegalArgumentException("signature algorithm must not be blank");
        boolean genericPss = "RSASSA-PSS".equalsIgnoreCase(algorithm);
        if (parameters == null) {
            if (genericPss) throw new IllegalArgumentException("RSASSA-PSS requires explicit signature parameters");
            return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        }
        if (!(parameters instanceof PSSParameterSpec pss)) {
            throw new IllegalArgumentException("Unsupported signature parameters: " + parameters.getClass().getName());
        }
        RsaPssParameters configuration = RsaPssParameters.fromParameterSpec(pss);
        AlgorithmIdentifier digest = digestIdentifier(configuration.digestAlgorithm());
        if (!genericPss) {
            AlgorithmIdentifier namedAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(namedAlgorithm.getAlgorithm())) {
                throw new IllegalArgumentException("PSSParameterSpec requires an RSA-PSS signature algorithm");
            }
            if (!RSASSAPSSparams.getInstance(namedAlgorithm.getParameters()).getHashAlgorithm().equals(digest)) {
                throw new IllegalArgumentException("RSA-PSS digest differs from the declared signature algorithm");
            }
        }
        RSASSAPSSparams encoded = new RSASSAPSSparams(digest,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digestIdentifier(configuration.mgfDigestAlgorithm())),
                new ASN1Integer(configuration.saltLength()), new ASN1Integer(PSSParameterSpec.TRAILER_FIELD_BC));
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, encoded);
    }

    private static AlgorithmIdentifier digestIdentifier(HashAlgorithm digest) {
        AlgorithmIdentifier identifier = new DefaultDigestAlgorithmIdentifierFinder().find(digest.jcaName());
        return new AlgorithmIdentifier(identifier.getAlgorithm(), DERNull.INSTANCE);
    }

    static ContentSigner contentSigner(PkiSigner signer) {
        Objects.requireNonNull(signer, "signer");
        AlgorithmIdentifier algorithm = algorithmIdentifier(signer.signatureAlgorithm(), signer.signatureParameters());
        return new ContentSigner() {
            private final ByteArrayOutputStream content = new ByteArrayOutputStream();
            @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return algorithm; }
            @Override public OutputStream getOutputStream() { return content; }
            @Override public byte[] getSignature() {
                try {
                    byte[] signature = signer.sign(content.toByteArray());
                    if (signature == null || signature.length == 0) {
                        throw new IllegalStateException("PkiSigner returned an empty signature");
                    }
                    return signature.clone();
                } catch (GeneralSecurityException e) {
                    throw new IllegalStateException("PkiSigner could not sign the certificate", e);
                }
            }
        };
    }
}
