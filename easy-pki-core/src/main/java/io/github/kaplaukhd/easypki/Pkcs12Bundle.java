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
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * An in-memory PKCS#12 bundle representing an identity or trusted certificates:
 * <ul>
 *   <li>a primary certificate ({@link #getCertificate()}),</li>
 *   <li>its private key ({@link #getPrivateKey()}, may be {@code null}
 *       for trust-only bundles), and</li>
 *   <li>the certificate chain for an identity, or every certificate entry for
 *       a trust-only bundle ({@link #getChain()}). The primary certificate is
 *       included as the first element.</li>
 * </ul>
 *
 * <p>Trust-only bundles export each certificate under a separate alias.
 * Bundles loaded from a trust-only keystore preserve all certificate entries
 * and their provider-reported aliases, including repeated certificates under
 * different aliases. Identity bundles export only their primary key entry
 * and its certificate chain.
 *
 * <p>Create via {@link PkiPkcs12#create()} or load via
 * {@link PkiPkcs12#load(Path, String)}.
 */
public final class Pkcs12Bundle {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final List<X509Certificate> chain;
    // One alias for an identity; one per chain element for a trust-only bundle.
    private final List<String> entryAliases;
    private final char[] password;

    Pkcs12Bundle(X509Certificate certificate,
                 PrivateKey privateKey,
                 List<X509Certificate> chain,
                 List<String> entryAliases,
                 char[] password) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.chain = List.copyOf(chain);
        this.entryAliases = List.copyOf(entryAliases);
        this.password = password.clone();
    }

    /** Returns the primary certificate, which is the leaf for an identity bundle. */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /** Returns the primary private key, or {@code null} for a trust-only bundle. */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns an immutable list containing the primary certificate first.
     * For an identity, its intermediates and root follow in chain order.
     * For a trust-only bundle, this contains every certificate entry, without
     * implying a chain relationship: builder order before export, and
     * lexicographic alias order after loading. For example, {@code "root-10"}
     * sorts before {@code "root-2"}. Repeated certificates are retained.
     */
    public List<X509Certificate> getChain() {
        return chain;
    }

    /**
     * Returns the primary entry alias. For a loaded trust-only bundle this
     * is the lexicographically first alias reported by the keystore provider.
     */
    public String getAlias() {
        return entryAliases.get(0);
    }

    /** Serialises the bundle to a PKCS#12 byte array. */
    public byte[] toBytes() {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            writeTo(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to serialise PKCS#12 bundle", e);
        }
    }

    /** Writes the bundle to the given file. Overwrites existing content. */
    public void saveTo(Path path) {
        Objects.requireNonNull(path, "path");
        try (OutputStream out = Files.newOutputStream(path)) {
            writeTo(out);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PKCS#12 file " + path, e);
        }
    }

    private void writeTo(OutputStream out) throws IOException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            if (privateKey != null) {
                ks.setKeyEntry(getAlias(), privateKey, password, chain.toArray(new X509Certificate[0]));
            } else {
                for (int i = 0; i < chain.size(); i++) {
                    ks.setCertificateEntry(entryAliases.get(i), chain.get(i));
                }
            }
            ks.store(out, password);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to build PKCS#12 keystore", e);
        }
    }
}
