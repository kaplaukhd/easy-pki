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
 * An in-memory PKCS#12 bundle with one primary entry consisting of:
 * <ul>
 *   <li>a leaf certificate ({@link #getCertificate()}),</li>
 *   <li>its private key ({@link #getPrivateKey()}, may be {@code null}
 *       for trust-only bundles), and</li>
 *   <li>the certificate chain above the leaf ({@link #getChain()}
 *       — the leaf is included as the first element).</li>
 * </ul>
 *
 * <p>Create via {@link PkiPkcs12#create()} or load via
 * {@link PkiPkcs12#load(Path, String)}.
 */
public final class Pkcs12Bundle {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final List<X509Certificate> chain;
    private final String alias;
    private final char[] password;

    Pkcs12Bundle(X509Certificate certificate,
                 PrivateKey privateKey,
                 List<X509Certificate> chain,
                 String alias,
                 char[] password) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.chain = List.copyOf(chain);
        this.alias = alias;
        this.password = password.clone();
    }

    /** Returns the primary (leaf) certificate. */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /** Returns the primary private key, or {@code null} for a trust-only bundle. */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the full certificate chain. The leaf is the first element; any
     * intermediates and the root follow.
     */
    public List<X509Certificate> getChain() {
        return chain;
    }

    /** Returns the entry alias used inside the keystore. */
    public String getAlias() {
        return alias;
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
                ks.setKeyEntry(alias, privateKey, password, chain.toArray(new X509Certificate[0]));
            } else {
                ks.setCertificateEntry(alias, certificate);
            }
            ks.store(out, password);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to build PKCS#12 keystore", e);
        }
    }
}
