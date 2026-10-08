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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/**
 * An immutable snapshot of explicitly trusted X.509 certificates.
 *
 * <p>A bundle contains anchors, not an identity or a certificate chain. Each
 * certificate supplied to {@link #of(Collection)} or a PEM loader is explicitly
 * trusted, including intermediate or end-entity certificates. No CA or
 * self-signature requirement is imposed on an explicitly selected anchor.
 * Supply only certificates intentionally selected as anchors; a peer identity
 * chain is not a trust bundle. Loading a keystore selects only trusted
 * certificate entries. Private-key entries and every certificate in their
 * identity chains are ignored.
 *
 * <p>Certificates are deduplicated by certificate equality (encoded content),
 * preserving first encounter order. Keystore entries are read in lexicographic
 * alias order. Empty bundles are allowed and establish no trust. No passwords
 * or private keys are retained. Supplied certificates are snapshotted through
 * their DER encoding, so changes to caller-provided certificate wrappers cannot
 * change the bundle.
 */
public final class TrustBundle {

    private final List<X509Certificate> trustAnchors;

    private TrustBundle(Collection<X509Certificate> anchors) {
        LinkedHashSet<X509Certificate> snapshots = new LinkedHashSet<>();
        for (X509Certificate certificate : List.copyOf(anchors)) {
            try {
                snapshots.add(PkiCertificates.fromDer(certificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Cannot snapshot trust anchor certificate", e);
            }
        }
        trustAnchors = List.copyOf(snapshots);
    }

    /**
     * Explicitly trusts all supplied certificates, preserving encounter order
     * and removing duplicates. The collection and certificate encodings are
     * copied; nulls are rejected.
     */
    public static TrustBundle of(Collection<X509Certificate> anchors) {
        Objects.requireNonNull(anchors, "anchors");
        return new TrustBundle(anchors);
    }

    /** Varargs overload of {@link #of(Collection)}; an empty array trusts nothing. */
    public static TrustBundle of(X509Certificate... anchors) {
        Objects.requireNonNull(anchors, "anchors");
        return of(Arrays.asList(anchors));
    }

    /** Returns the immutable, deduplicated list of explicitly trusted certificates. */
    public List<X509Certificate> getTrustAnchors() {
        return trustAnchors;
    }

    /**
     * Returns a new bundle containing this bundle followed by the supplied
     * bundles, preserving first encounter order and removing duplicates.
     * Neither this bundle nor the supplied bundles is changed. Nulls are rejected.
     */
    public TrustBundle merge(TrustBundle... bundles) {
        Objects.requireNonNull(bundles, "bundles");
        List<X509Certificate> anchors = new ArrayList<>(trustAnchors);
        for (TrustBundle bundle : bundles) {
            anchors.addAll(Objects.requireNonNull(bundle, "bundle").trustAnchors);
        }
        return of(anchors);
    }

    /**
     * Explicitly trusts every certificate in the PEM string. Empty input and
     * non-certificate PEM blocks are rejected by {@link PkiCertificates#allFromPem(String)}.
     */
    public static TrustBundle fromPem(String pem) {
        return of(PkiCertificates.allFromPem(pem));
    }

    /** Parses UTF-8 PEM bytes; every supplied certificate is explicitly trusted. */
    public static TrustBundle fromPem(byte[] pem) {
        Objects.requireNonNull(pem, "pem");
        return fromPem(new String(pem, StandardCharsets.UTF_8));
    }

    /** Reads a PEM file; every supplied certificate is explicitly trusted. */
    public static TrustBundle fromPem(Path path) {
        return of(PkiCertificates.allFromFile(path));
    }

    /**
     * Snapshots the trusted X.509 certificate entries of a loaded JCA keystore
     * in lexicographic alias order. Key entries and their chains are ignored.
     * Changes to the keystore after this call do not change the bundle.
     *
     * @throws IllegalArgumentException if a trusted entry is not an X.509 certificate
     * @throws IllegalStateException if the keystore cannot be read
     */
    public static TrustBundle fromKeyStore(KeyStore keyStore) {
        Objects.requireNonNull(keyStore, "keyStore");
        try {
            List<String> aliases = Collections.list(keyStore.aliases());
            Collections.sort(aliases);
            List<X509Certificate> anchors = new ArrayList<>();
            for (String alias : aliases) {
                if (!keyStore.isCertificateEntry(alias)) {
                    continue;
                }
                Certificate certificate = keyStore.getCertificate(alias);
                if (!(certificate instanceof X509Certificate anchor)) {
                    throw new IllegalArgumentException(
                            "Trusted entry '" + alias + "' is not an X.509 certificate");
                }
                anchors.add(anchor);
            }
            return of(anchors);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to read trust store", e);
        }
    }

    /**
     * Loads trusted certificate entries from PKCS#12 bytes. Key entries are
     * ignored. The password is required, copied for loading and the copy is
     * cleared afterwards; pass an empty array for an empty password.
     *
     * @throws IllegalArgumentException if the password is incorrect
     * @throws UncheckedIOException if the encoded store cannot be read
     */
    public static TrustBundle fromPkcs12(byte[] data, char[] password) {
        return load(data, password, "PKCS12", "PKCS#12 bytes");
    }

    /** Reads trusted certificate entries from a PKCS#12 file; see {@link #fromPkcs12(byte[], char[])}. */
    public static TrustBundle fromPkcs12(Path path, char[] password) {
        return load(path, password, "PKCS12");
    }

    /**
     * Loads trusted certificate entries from JKS bytes. Key entries are ignored.
     * The password is required, copied for loading and the copy is cleared
     * afterwards; pass an empty array for an empty password.
     *
     * @throws IllegalArgumentException if the password is incorrect
     * @throws UncheckedIOException if the encoded store cannot be read
     */
    public static TrustBundle fromJks(byte[] data, char[] password) {
        return load(data, password, "JKS", "JKS bytes");
    }

    /** Reads trusted certificate entries from a JKS file; see {@link #fromJks(byte[], char[])}. */
    public static TrustBundle fromJks(Path path, char[] password) {
        return load(path, password, "JKS");
    }

    private static TrustBundle load(Path path, char[] password, String type) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(password, "password");
        try {
            return load(Files.readAllBytes(path), password, type, path.toString());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read trust store from " + path, e);
        }
    }

    private static TrustBundle load(byte[] data, char[] password, String type, String source) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(password, "password");
        char[] passwordCopy = password.clone();
        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(new ByteArrayInputStream(data), passwordCopy);
            return fromKeyStore(keyStore);
        } catch (IOException e) {
            if (e.getCause() instanceof UnrecoverableKeyException) {
                throw new IllegalArgumentException("Wrong " + type + " password for " + source, e);
            }
            throw new UncheckedIOException("Failed to read " + type + " trust store from " + source, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to load " + type + " trust store from " + source, e);
        } finally {
            Arrays.fill(passwordCopy, '\0');
        }
    }
}
