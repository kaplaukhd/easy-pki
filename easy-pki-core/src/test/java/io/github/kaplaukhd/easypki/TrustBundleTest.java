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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TrustBundleTest {

    private static final KeyPair ROOT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT_A = root("A", ROOT_KEYS);
    private static final X509Certificate ROOT_B = root("B", PkiKeys.ec(Curve.P_256));
    private static final KeyPair INTERMEDIATE_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate INTERMEDIATE = PkiCertificate.signed()
            .subject("CN=Trust Intermediate").publicKey(INTERMEDIATE_KEYS.getPublic())
            .issuer(ROOT_A, ROOT_KEYS.getPrivate()).pathLength(0)
            .validFor(Duration.ofDays(180)).build();
    private static final KeyPair LEAF_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate LEAF = PkiCertificate.signed()
            .subject("CN=Trust Leaf").publicKey(LEAF_KEYS.getPublic())
            .issuer(INTERMEDIATE, INTERMEDIATE_KEYS.getPrivate())
            .validFor(Duration.ofDays(30)).build();

    @TempDir
    Path temporary;

    @Test
    void explicitCertificatesAreSnapshottedAndDeduplicatedByContent() {
        X509Certificate copied = PkiCertificates.fromDer(PkiCertificates.toDer(ROOT_A));
        List<X509Certificate> source = new ArrayList<>(List.of(ROOT_B, ROOT_A, copied));
        TrustBundle bundle = TrustBundle.of(source);
        source.clear();

        assertThat(bundle.getTrustAnchors()).containsExactly(ROOT_B, ROOT_A);
        assertThatThrownBy(() -> bundle.getTrustAnchors().add(INTERMEDIATE))
                .isInstanceOf(UnsupportedOperationException.class);
        X509Certificate[] array = {ROOT_A};
        TrustBundle fromArray = TrustBundle.of(array);
        array[0] = ROOT_B;
        assertThat(fromArray.getTrustAnchors()).containsExactly(ROOT_A);
    }

    @Test
    void mutableCertificateWrappersCannotChangeCreatedBundle() {
        MutableCertificate supplied = new MutableCertificate(ROOT_A);
        TrustBundle bundle = TrustBundle.of(supplied, ROOT_A, ROOT_B);
        supplied.certificate = ROOT_B;

        assertThat(bundle.getTrustAnchors()).containsExactly(ROOT_A, ROOT_B);
        assertThat(bundle.getTrustAnchors().get(0)).isNotSameAs(supplied);
        assertThat(bundle.getTrustAnchors().get(0).getPublicKey()).isEqualTo(ROOT_A.getPublicKey());
    }

    @Test
    void explicitIntermediateAndLeafAreNotFilteredByHeuristics() {
        assertThat(TrustBundle.of(INTERMEDIATE, LEAF).getTrustAnchors())
                .containsExactly(INTERMEDIATE, LEAF);
    }

    @Test
    void mergingPreservesAllIndependentRootsInFirstEncounterOrder() {
        TrustBundle first = TrustBundle.of(ROOT_B, ROOT_A);
        TrustBundle second = TrustBundle.of(ROOT_A, INTERMEDIATE);
        TrustBundle merged = first.merge(second, TrustBundle.of(ROOT_B, LEAF));

        assertThat(merged.getTrustAnchors()).containsExactly(ROOT_B, ROOT_A, INTERMEDIATE, LEAF);
        assertThat(first.getTrustAnchors()).containsExactly(ROOT_B, ROOT_A);
        assertThat(second.getTrustAnchors()).containsExactly(ROOT_A, INTERMEDIATE);
        assertThat(TrustBundle.of().merge(first).getTrustAnchors()).containsExactly(ROOT_B, ROOT_A);
    }

    @Test
    void pemStringBytesAndFilePreserveEveryDeclaredAnchor() throws Exception {
        String pem = PkiCertificates.toPem(List.of(ROOT_B, ROOT_A, ROOT_B, INTERMEDIATE));
        Path path = temporary.resolve("anchors.pem");
        Files.writeString(path, pem);
        List<X509Certificate> expected = List.of(ROOT_B, ROOT_A, INTERMEDIATE);

        assertThat(TrustBundle.fromPem(pem).getTrustAnchors()).isEqualTo(expected);
        assertThat(TrustBundle.fromPem(pem.getBytes(StandardCharsets.UTF_8)).getTrustAnchors())
                .isEqualTo(expected);
        assertThat(TrustBundle.fromPem(path).merge(TrustBundle.of(ROOT_A)).getTrustAnchors())
                .isEqualTo(expected);
    }

    @Test
    void pemRejectsEmptyAndMixedPrivateKeyInput() {
        assertThatIllegalArgumentException().isThrownBy(() -> TrustBundle.fromPem(""))
                .withMessageContaining("No certificates");
        String mixed = PkiCertificates.toPem(ROOT_A) + PkiPrivateKeys.toPem(ROOT_KEYS.getPrivate());
        assertThatIllegalArgumentException().isThrownBy(() -> TrustBundle.fromPem(mixed))
                .withMessageContaining("Expected only X.509 certificates");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "JKS"})
    void storeLoadersKeepAllTrustedCertificatesAndIgnoreEntireIdentityChain(String type) throws Exception {
        char[] password = "trust-password".toCharArray();
        char[] originalPassword = password.clone();
        KeyStore store = emptyStore(type);
        store.setKeyEntry("0-identity", LEAF_KEYS.getPrivate(), password,
                new X509Certificate[]{LEAF, INTERMEDIATE, ROOT_A});
        store.setCertificateEntry("z-root-b", ROOT_B);
        store.setCertificateEntry("a-root-a", ROOT_A);
        store.setCertificateEntry("b-root-a-copy", ROOT_A);
        TrustBundle snapshot = TrustBundle.fromKeyStore(store);
        byte[] data = bytes(store, password);
        Path path = temporary.resolve("anchors." + type.toLowerCase(java.util.Locale.ROOT));
        Files.write(path, data);

        TrustBundle fromBytes = type.equals("JKS")
                ? TrustBundle.fromJks(data, password) : TrustBundle.fromPkcs12(data, password);
        TrustBundle fromPath = type.equals("JKS")
                ? TrustBundle.fromJks(path, password) : TrustBundle.fromPkcs12(path, password);
        store.deleteEntry("a-root-a");
        store.setCertificateEntry("new-intermediate", INTERMEDIATE);

        assertThat(snapshot.getTrustAnchors()).containsExactly(ROOT_A, ROOT_B);
        assertThat(fromBytes.getTrustAnchors()).containsExactly(ROOT_A, ROOT_B);
        assertThat(fromPath.getTrustAnchors()).containsExactly(ROOT_A, ROOT_B);
        assertThat(password).isEqualTo(originalPassword);
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "JKS"})
    void privateKeyChainsDoNotCreateAnyTrustAnchors(String type) throws Exception {
        KeyStore store = emptyStore(type);
        char[] password = "secret".toCharArray();
        store.setKeyEntry("identity", LEAF_KEYS.getPrivate(), password,
                new X509Certificate[]{LEAF, INTERMEDIATE, ROOT_A});
        byte[] data = bytes(store, password);
        assertThat(TrustBundle.fromKeyStore(store).getTrustAnchors()).isEmpty();
        assertThat((type.equals("JKS") ? TrustBundle.fromJks(data, password)
                : TrustBundle.fromPkcs12(data, password)).getTrustAnchors()).isEmpty();
        assertThat(TrustBundle.fromKeyStore(emptyStore(type)).getTrustAnchors()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "JKS"})
    void wrongPasswordPreservesCallerPasswordAndReportsSource(String type) throws Exception {
        KeyStore store = emptyStore(type);
        store.setCertificateEntry("root", ROOT_A);
        Path path = temporary.resolve("wrong-password-store");
        Files.write(path, bytes(store, "correct".toCharArray()));
        char[] wrong = "wrong".toCharArray();
        assertThatIllegalArgumentException().isThrownBy(() -> {
            if (type.equals("JKS")) {
                TrustBundle.fromJks(path, wrong);
            } else {
                TrustBundle.fromPkcs12(path, wrong);
            }
        }).withMessageContaining("password").withMessageContaining(path.toString());
        assertThat(wrong).isEqualTo("wrong".toCharArray());
    }

    @Test
    void missingAndInvalidSourcesFailClearly() {
        Path missing = temporary.resolve("missing-store");
        assertThatThrownBy(() -> TrustBundle.fromPkcs12(missing, new char[0]))
                .isInstanceOf(UncheckedIOException.class).hasMessageContaining(missing.toString());
        assertThatThrownBy(() -> TrustBundle.fromJks(missing, new char[0]))
                .isInstanceOf(UncheckedIOException.class).hasMessageContaining(missing.toString());
        assertThatThrownBy(() -> TrustBundle.fromPem(missing))
                .isInstanceOf(UncheckedIOException.class).hasMessageContaining(missing.toString());
        assertThatThrownBy(() -> TrustBundle.fromPkcs12(new byte[]{1, 2, 3}, new char[0]))
                .isInstanceOf(UncheckedIOException.class).hasMessageContaining("PKCS#12 bytes");
        assertThatThrownBy(() -> TrustBundle.fromJks(new byte[]{1, 2, 3}, new char[0]))
                .isInstanceOf(UncheckedIOException.class).hasMessageContaining("JKS bytes");
    }

    @Test
    void uninitializedKeyStoreFailsClearly() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        assertThatIllegalStateException().isThrownBy(() -> TrustBundle.fromKeyStore(store))
                .withMessageContaining("Failed to read trust store");
    }

    @Test
    void nullInputsAndNullElementsAreRejected() {
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.of((Collection<X509Certificate>) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.of((X509Certificate[]) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.of(Arrays.asList(ROOT_A, null)));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.of().merge((TrustBundle[]) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.of().merge(TrustBundle.of(), null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromKeyStore(null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPem((String) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPem((byte[]) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPem((Path) null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPkcs12((byte[]) null, new char[0]));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPkcs12((Path) null, new char[0]));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromJks((byte[]) null, new char[0]));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromJks((Path) null, new char[0]));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromPkcs12(new byte[0], null));
        assertThatNullPointerException().isThrownBy(() -> TrustBundle.fromJks(new byte[0], null));
    }

    // Only encoded content is meaningful on this wrapper. Snapshotting must not
    // retain the wrapper or rely on its other mutable, caller-controlled getters.
    @SuppressWarnings("deprecation")
    private static final class MutableCertificate extends X509Certificate {
        private static final long serialVersionUID = 1L;
        private X509Certificate certificate;

        MutableCertificate(X509Certificate certificate) { this.certificate = certificate; }
        @Override public byte[] getEncoded() throws CertificateEncodingException { return certificate.getEncoded(); }
        @Override public void checkValidity() { throw new UnsupportedOperationException(); }
        @Override public void checkValidity(Date date) { throw new UnsupportedOperationException(); }
        @Override public int getVersion() { throw new UnsupportedOperationException(); }
        @Override public BigInteger getSerialNumber() { throw new UnsupportedOperationException(); }
        @Override public Principal getIssuerDN() { throw new UnsupportedOperationException(); }
        @Override public Principal getSubjectDN() { throw new UnsupportedOperationException(); }
        @Override public Date getNotBefore() { throw new UnsupportedOperationException(); }
        @Override public Date getNotAfter() { throw new UnsupportedOperationException(); }
        @Override public byte[] getTBSCertificate() { throw new UnsupportedOperationException(); }
        @Override public byte[] getSignature() { throw new UnsupportedOperationException(); }
        @Override public String getSigAlgName() { throw new UnsupportedOperationException(); }
        @Override public String getSigAlgOID() { throw new UnsupportedOperationException(); }
        @Override public byte[] getSigAlgParams() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getIssuerUniqueID() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getSubjectUniqueID() { throw new UnsupportedOperationException(); }
        @Override public boolean[] getKeyUsage() { throw new UnsupportedOperationException(); }
        @Override public int getBasicConstraints() { throw new UnsupportedOperationException(); }
        @Override public void verify(PublicKey key) { throw new UnsupportedOperationException(); }
        @Override public void verify(PublicKey key, String provider) { throw new UnsupportedOperationException(); }
        @Override public String toString() { return "Mutable test certificate"; }
        @Override public PublicKey getPublicKey() { throw new UnsupportedOperationException(); }
        @Override public Set<String> getCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { throw new UnsupportedOperationException(); }
        @Override public byte[] getExtensionValue(String oid) { throw new UnsupportedOperationException(); }
        @Override public boolean hasUnsupportedCriticalExtension() { throw new UnsupportedOperationException(); }
    }

    private static X509Certificate root(String name, KeyPair keys) {
        return PkiCertificate.selfSigned().subject("CN=Trust Root " + name)
                .keyPair(keys).isCA(true).validFor(Duration.ofDays(365)).build();
    }

    private static KeyStore emptyStore(String type) throws Exception {
        KeyStore store = KeyStore.getInstance(type);
        store.load(null, null);
        return store;
    }

    private static byte[] bytes(KeyStore store, char[] password) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, password);
        return output.toByteArray();
    }
}
