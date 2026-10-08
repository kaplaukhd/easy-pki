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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.EdECKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.List;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

class Ed25519Test {

    private static final String ED25519_OID = "1.3.101.112";

    @Test
    void generatesDistinctEd25519KeysWithStandardEncodings() {
        Provider[] providers = Security.getProviders();
        KeyPair first = PkiKeys.ed25519();
        KeyPair second = PkiKeys.ed25519();
        assertThat(first.getPublic().getAlgorithm()).isEqualTo("Ed25519");
        assertThat(first.getPrivate().getAlgorithm()).isEqualTo("Ed25519");
        assertThat(first.getPublic().getFormat()).isEqualTo("X.509");
        assertThat(first.getPrivate().getFormat()).isEqualTo("PKCS#8");
        assertThat(first.getPublic().getEncoded()).isNotEqualTo(second.getPublic().getEncoded());
        assertThat(first.getPrivate().getEncoded()).isNotEqualTo(second.getPrivate().getEncoded());
        var spki = SubjectPublicKeyInfo.getInstance(first.getPublic().getEncoded());
        assertThat(spki.getAlgorithm().getAlgorithm().getId()).isEqualTo(ED25519_OID);
        assertThat(spki.getAlgorithm().getParameters()).isNull();
        assertThat(spki.getPublicKeyData().getBytes()).hasSize(32);
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void bothBuildersInferEd25519AndIssuedAlgorithmComesFromIssuer() throws Exception {
        Provider[] providers = Security.getProviders();
        KeyPair rootKeys = PkiKeys.ed25519();
        X509Certificate root = selfSigned(rootKeys);
        KeyPair leafKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate leaf = PkiCertificate.signed().subject("CN=EC Subject")
                .keyPair(leafKeys).issuer(root, rootKeys.getPrivate())
                .validFor(Duration.ofDays(1)).build();
        assertSignature(root, root);
        assertSignature(leaf, root);
        assertThat(leaf.getPublicKey().getAlgorithm()).isEqualTo("EC");
        assertThat(PkiCertInfo.of(root).isSelfSigned()).isTrue();
        assertThat(PkiCertInfo.of(leaf).isSelfSigned()).isFalse();
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void jdkEdDsaKeysUseTheirNamedParameters() throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertThat(keys.getPrivate()).isInstanceOf(EdECKey.class);
        assertThat(keys.getPrivate().getAlgorithm()).isEqualTo("EdDSA");
        X509Certificate root = selfSigned(keys);
        assertSignature(root, root);
        X509Certificate leaf = PkiCertificate.signed().subject("CN=JDK Ed25519 Leaf")
                .keyPair(PkiKeys.ed25519()).issuer(root, keys.getPrivate())
                .validFor(Duration.ofDays(1)).build();
        assertSignature(leaf, root);
        assertThat(PkiSigner.jca(keys.getPrivate()).signatureAlgorithm()).isEqualTo("Ed25519");
    }

    @Test
    void ed448IsNeverInferredAsEd25519() throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
        assertThat(keys.getPrivate().getAlgorithm()).isEqualTo("EdDSA");
        assertThat(((EdECKey) keys.getPrivate()).getParams().getName()).isEqualTo("Ed448");
        assertThatIllegalStateException().isThrownBy(() -> selfSigned(keys))
                .withMessageContaining("No default signature algorithm");
        assertThatIllegalStateException().isThrownBy(() -> PkiSigner.jca(keys.getPrivate()))
                .withMessageContaining("No default signature algorithm");
        X509Certificate explicit = PkiCertificate.selfSigned().subject("CN=Explicit Ed448")
                .keyPair(keys).signatureAlgorithm("Ed448").validFor(Duration.ofDays(1)).build();
        assertThat(explicit.getSigAlgOID()).isEqualTo("1.3.101.113");
        explicit.verify(explicit.getPublicKey());
    }

    @Test
    void certificateAndKeyRoundTripsRemainUsableWithoutRegisteringProviders() throws Exception {
        Provider[] providers = Security.getProviders();
        KeyPair keys = PkiKeys.ed25519();
        X509Certificate original = selfSigned(keys);
        X509Certificate pem = PkiCertificates.fromPem(PkiCertificates.toPem(original));
        X509Certificate der = PkiCertificates.fromDer(PkiCertificates.toDer(original));
        X509Certificate independent = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(PkiCertificates.toDer(original)));
        for (X509Certificate reloaded : List.of(pem, der, independent)) {
            assertThat(reloaded.getEncoded()).isEqualTo(original.getEncoded());
            assertSignature(reloaded, reloaded);
        }

        PrivateKey plain = PkiPrivateKeys.fromPem(PkiPrivateKeys.toPem(keys.getPrivate()));
        // Lower iteration count keeps this format compatibility fixture fast.
        var options = new PemEncryptionOptions(10_000, PemEncryptionOptions.Prf.HMAC_SHA256);
        PrivateKey encrypted = PkiPrivateKeys.fromPem(
                PkiPrivateKeys.toPem(keys.getPrivate(), "password", options), "password");
        PrivateKey jdk = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(plain.getEncoded()));
        assertThat(jdk.getAlgorithm()).isEqualTo("EdDSA");

        byte[] pkcs12 = PkiPkcs12.create().certificate(original).privateKey(keys.getPrivate())
                .alias("ed25519").password("password").build().toBytes();
        Pkcs12Bundle loaded = PkiPkcs12.load(pkcs12, "password");
        assertThat(loaded.getCertificate()).isEqualTo(original);
        assertThat(loaded.getChain()).containsExactly(original);
        assertThat(loaded.getPrivateKey().getAlgorithm()).isEqualTo("EdDSA");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), "password".toCharArray());
        assertThat(store.getCertificate("ed25519")).isEqualTo(original);
        PrivateKey independentKey = (PrivateKey) store.getKey("ed25519", "password".toCharArray());

        for (PrivateKey reloaded : List.of(plain, encrypted, jdk, loaded.getPrivateKey(), independentKey)) {
            X509Certificate rebuilt = selfSigned(new KeyPair(original.getPublicKey(), reloaded));
            assertSignature(rebuilt, original);
            X509Certificate issued = PkiCertificate.signed().subject("CN=Reloaded issuer")
                    .keyPair(PkiKeys.ed25519()).issuer(original, reloaded)
                    .validFor(Duration.ofDays(1)).build();
            assertSignature(issued, original);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(original.getPublicKey());
            byte[] message = new byte[] {1, 2, 3};
            verifier.update(message);
            assertThat(verifier.verify(PkiSigner.jca(reloaded).sign(message))).isTrue();
        }
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    private static X509Certificate selfSigned(KeyPair keys) {
        return PkiCertificate.selfSigned().subject("CN=Ed25519 Root").keyPair(keys)
                .isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .validFor(Duration.ofDays(30)).build();
    }

    private static void assertSignature(X509Certificate certificate, X509Certificate issuer)
            throws Exception {
        assertThat(certificate.getSigAlgOID()).isEqualTo(ED25519_OID);
        var holder = new X509CertificateHolder(certificate.getEncoded());
        assertThat(holder.getSignatureAlgorithm().getParameters()).isNull();
        assertThat(holder.toASN1Structure().getTBSCertificate().getSignature())
                .isEqualTo(holder.getSignatureAlgorithm());
        Signature signature = Signature.getInstance("Ed25519");
        assertThat(signature.getProvider().getName()).isNotEqualTo("BC");
        signature.initVerify(issuer.getPublicKey());
        signature.update(certificate.getTBSCertificate());
        assertThat(signature.verify(certificate.getSignature())).isTrue();
        certificate.verify(issuer.getPublicKey());
    }
}
