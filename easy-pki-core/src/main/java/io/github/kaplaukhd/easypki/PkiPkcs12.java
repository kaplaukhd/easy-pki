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
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Entry point for PKCS#12 keystore creation and loading.
 *
 * <h2>Create</h2>
 * <pre>{@code
 * Pkcs12Bundle bundle = PkiPkcs12.create()
 *     .certificate(leafCert)
 *     .privateKey(leafKey)
 *     .chain(intermediate, root)
 *     .password("changeit")
 *     .build();
 * bundle.saveTo(Path.of("keystore.p12"));
 * }</pre>
 *
 * <h2>Load</h2>
 * <pre>{@code
 * Pkcs12Bundle loaded = PkiPkcs12.load(Path.of("keystore.p12"), "changeit");
 * X509Certificate cert  = loaded.getCertificate();
 * PrivateKey      key   = loaded.getPrivateKey();
 * List<X509Certificate> chain = loaded.getChain();
 * }</pre>
 */
public final class PkiPkcs12 {

    private PkiPkcs12() {
        // Utility class.
    }

    /** Starts a new PKCS#12 bundle builder. */
    public static Pkcs12Builder create() {
        return new Pkcs12Builder();
    }

    /** Loads a bundle from a PKCS#12 file. */
    public static Pkcs12Bundle load(Path path, String password) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(password, "password");
        try (InputStream in = Files.newInputStream(path)) {
            return load(in, password);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PKCS#12 file " + path, e);
        }
    }

    /** Loads a bundle from a PKCS#12 byte array. */
    public static Pkcs12Bundle load(byte[] data, String password) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(password, "password");
        try (InputStream in = new ByteArrayInputStream(data)) {
            return load(in, password);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PKCS#12 data", e);
        }
    }

    /** Loads a bundle from a PKCS#12 {@link InputStream}. The stream is <em>not</em> closed. */
    public static Pkcs12Bundle load(InputStream in, String password) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(password, "password");
        char[] pwd = password.toCharArray();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try {
                ks.load(in, pwd);
            } catch (IOException e) {
                // JCA reports bad password as IOException caused by UnrecoverableKeyException.
                if (e.getCause() instanceof UnrecoverableKeyException) {
                    throw new IllegalArgumentException("Wrong PKCS#12 password", e);
                }
                throw new UncheckedIOException("Failed to load PKCS#12 keystore", e);
            }

            String alias = findPrimaryAlias(ks);
            Certificate[] rawChain = ks.getCertificateChain(alias);
            X509Certificate leafCert;
            List<X509Certificate> chain;
            if (rawChain != null && rawChain.length > 0) {
                chain = toX509Chain(rawChain);
                leafCert = chain.get(0);
            } else {
                // Certificate-only entry (no private key).
                Certificate c = ks.getCertificate(alias);
                leafCert = asX509(c);
                chain = Collections.singletonList(leafCert);
            }

            PrivateKey privateKey = null;
            if (ks.isKeyEntry(alias)) {
                Key key = ks.getKey(alias, pwd);
                if (key instanceof PrivateKey pk) {
                    privateKey = pk;
                } else if (key != null) {
                    throw new IllegalArgumentException(
                            "Entry '" + alias + "' contains a non-private key of type "
                                    + key.getClass().getSimpleName());
                }
            }

            return new Pkcs12Bundle(leafCert, privateKey, chain, alias, pwd);
        } catch (UnrecoverableKeyException e) {
            throw new IllegalArgumentException("Wrong PKCS#12 key password", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to read PKCS#12 keystore", e);
        } finally {
            java.util.Arrays.fill(pwd, '\0');
        }
    }

    private static String findPrimaryAlias(KeyStore ks) throws GeneralSecurityException {
        String keyAlias = null;
        String certAlias = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a) && keyAlias == null) {
                keyAlias = a;
            } else if (ks.isCertificateEntry(a) && certAlias == null) {
                certAlias = a;
            }
        }
        if (keyAlias != null) {
            return keyAlias;
        }
        if (certAlias != null) {
            return certAlias;
        }
        throw new IllegalArgumentException("PKCS#12 keystore contains no entries");
    }

    private static List<X509Certificate> toX509Chain(Certificate[] raw) {
        List<X509Certificate> out = new ArrayList<>(raw.length);
        for (Certificate c : raw) {
            out.add(asX509(c));
        }
        return out;
    }

    private static X509Certificate asX509(Certificate c) {
        if (c instanceof X509Certificate x) {
            return x;
        }
        throw new IllegalArgumentException(
                "PKCS#12 entry is not an X.509 certificate: " + c.getType());
    }
}
