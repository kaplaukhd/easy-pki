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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.io.StringReader;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.Test;

class PkiPrivateKeyProtectionTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path directory;

    @Test
    void defaultWriterEncodesExplicitModernKdfParameters() throws Exception {
        var key = PkiKeys.ec(Curve.P_256).getPrivate();
        String pem = PkiPrivateKeys.toPem(key, "fixture-password");
        try (var parser = new PEMParser(new StringReader(pem))) {
            var info = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
            var params = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
            var kdf = PBKDF2Params.getInstance(params.getKeyDerivationFunc().getParameters());
            assertThat(params.getEncryptionScheme().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_aes256_CBC);
            assertThat(kdf.getPrf().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_hmacWithSHA256);
            assertThat(kdf.getIterationCount().intValueExact()).isEqualTo(600_000);
            assertThat(kdf.getSalt().length).isGreaterThanOrEqualTo(16);
        }
        assertThat(PkiPrivateKeys.fromPem(pem, "fixture-password").getEncoded()).isEqualTo(key.getEncoded());
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(PemEncryptionOptions.Prf.class)
    void explicitPolicyIsSerializedAndCharPasswordWorksForAllInputs(PemEncryptionOptions.Prf prf) throws Exception {
        var options = new PemEncryptionOptions(10_000, prf); // Low cost only to keep this fixture fast.
        var key = PkiKeys.ec(Curve.P_256).getPrivate();
        char[] password = "long-test-password".toCharArray();
        char[] original = password.clone();
        String pem = PkiPrivateKeys.toPem(key, password, options);
        try (var parser = new PEMParser(new StringReader(pem))) {
            var info = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
            var params = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
            var kdf = PBKDF2Params.getInstance(params.getKeyDerivationFunc().getParameters());
            assertThat(kdf.getIterationCount().intValueExact()).isEqualTo(10_000);
            assertThat(kdf.getPrf().getAlgorithm()).isEqualTo(prf == PemEncryptionOptions.Prf.HMAC_SHA256
                    ? PKCSObjectIdentifiers.id_hmacWithSHA256 : PKCSObjectIdentifiers.id_hmacWithSHA512);
        }
        assertThat(PkiPrivateKeys.fromPem(pem, password).getEncoded()).isEqualTo(key.getEncoded());
        assertThat(PkiPrivateKeys.fromPem(new StringReader(pem), password).getEncoded()).isEqualTo(key.getEncoded());
        assertThat(PkiPrivateKeys.fromPem(new java.io.ByteArrayInputStream(
                pem.getBytes(java.nio.charset.StandardCharsets.UTF_8)), password).getEncoded()).isEqualTo(key.getEncoded());
        var path = directory.resolve("key.pem");
        PkiPrivateKeys.toFile(key, path, password, options);
        assertThat(PkiPrivateKeys.fromFile(path, password).getEncoded()).isEqualTo(key.getEncoded());
        PkiPrivateKeys.toFile(key, path, "long-test-password", options);
        assertThat(PkiPrivateKeys.fromFile(path, password).getEncoded()).isEqualTo(key.getEncoded());
        assertThat(password).isEqualTo(original);
    }

    @Test
    void passwordsAreUnchangedOnFailureAndInvalidPolicyDoesNotTruncateFile() throws Exception {
        var key = PkiKeys.ec(Curve.P_256).getPrivate();
        var options = new PemEncryptionOptions(10_000, PemEncryptionOptions.Prf.HMAC_SHA256);
        String pem = PkiPrivateKeys.toPem(key, "correct", options);
        char[] wrong = "wrong".toCharArray();
        assertThatThrownBy(() -> PkiPrivateKeys.fromPem(pem, wrong)).isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> PkiPrivateKeys.fromPem("not PEM", wrong)).isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> PkiPrivateKeys.toFile(key, directory, wrong, options)).isInstanceOf(RuntimeException.class);
        assertThat(wrong).isEqualTo("wrong".toCharArray());
        var path = directory.resolve("untouched.pem");
        java.nio.file.Files.writeString(path, "existing-content");
        assertThatThrownBy(() -> PkiPrivateKeys.toFile(key, path, wrong, null)).isInstanceOf(NullPointerException.class);
        assertThat(java.nio.file.Files.readString(path)).isEqualTo("existing-content");
        assertThatThrownBy(() -> new PemEncryptionOptions(0, PemEncryptionOptions.Prf.HMAC_SHA256))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PemEncryptionOptions(-1, PemEncryptionOptions.Prf.HMAC_SHA256))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PemEncryptionOptions(1, null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void everyWriteHasIndependentSaltAndIv() throws Exception {
        var key = PkiKeys.ec(Curve.P_256).getPrivate();
        var options = new PemEncryptionOptions(10_000, PemEncryptionOptions.Prf.HMAC_SHA256);
        String first = PkiPrivateKeys.toPem(key, "password", options);
        String second = PkiPrivateKeys.toPem(key, "password", options);
        try (var a = new PEMParser(new StringReader(first)); var b = new PEMParser(new StringReader(second))) {
            var p1 = PBES2Parameters.getInstance(((PKCS8EncryptedPrivateKeyInfo) a.readObject()).getEncryptionAlgorithm().getParameters());
            var p2 = PBES2Parameters.getInstance(((PKCS8EncryptedPrivateKeyInfo) b.readObject()).getEncryptionAlgorithm().getParameters());
            assertThat(PBKDF2Params.getInstance(p1.getKeyDerivationFunc().getParameters()).getSalt())
                    .isNotEqualTo(PBKDF2Params.getInstance(p2.getKeyDerivationFunc().getParameters()).getSalt());
            assertThat(p1.getEncryptionScheme().getParameters()).isNotEqualTo(p2.getEncryptionScheme().getParameters());
        }
    }

}
