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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Per-call JCA signature state; the key handle remains owned by the application. */
final class JcaPkiSigner implements PkiSigner {
    private final PrivateKey key;
    private final String algorithm;
    private final Provider provider;
    private final AlgorithmIdentifier identifier;
    private final PSSParameterSpec parameters;

    JcaPkiSigner(PrivateKey key, String algorithm, Provider provider) {
        this(key, algorithm, provider, null);
    }

    JcaPkiSigner(PrivateKey key, String algorithm, Provider provider, PSSParameterSpec parameters) {
        this.key = Objects.requireNonNull(key, "key");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.parameters = parameters == null ? null : RsaPssParameters.fromParameterSpec(parameters).toParameterSpec();
        this.identifier = PkiSignerSupport.algorithmIdentifier(algorithm, this.parameters);
        this.provider = provider;
    }

    @Override
    public String signatureAlgorithm() { return algorithm; }

    @Override
    public PSSParameterSpec signatureParameters() { return parameters; }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {
        Objects.requireNonNull(content, "content");
        if (parameters != null) {
            // The generic JCA algorithm preserves independent digest/MGF choices;
            // digest-specific aliases can impose provider-dependent defaults.
            Signature signature = provider == null ? Signature.getInstance(algorithm)
                    : Signature.getInstance(algorithm, provider);
            // Default JCA selection must see the key handle before parameters
            // pin a provider that may not support that handle.
            signature.initSign(key);
            signature.setParameter(parameters);
            signature.update(content);
            return signature.sign();
        }
        try {
            // Retains existing BC-to-JCA name/parameter handling. Fresh state
            // for each call avoids mixing data between repeated/concurrent builds.
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder(algorithm);
            if (provider != null) builder.setProvider(provider);
            ContentSigner signer = builder.build(key);
            if (!identifier.equals(signer.getAlgorithmIdentifier())) {
                throw new SignatureException("JCA signer parameters differ from the declared X.509 algorithm");
            }
            try (var output = signer.getOutputStream()) {
                output.write(content);
            }
            return signer.getSignature();
        } catch (OperatorCreationException | IOException | RuntimeOperatorException e) {
            throw new GeneralSecurityException("JCA signing failed for " + algorithm, e);
        }
    }
}
