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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Fluent builder for PKCS#12 bundles. Obtain via {@link PkiPkcs12#create()}.
 *
 * <pre>{@code
 * Pkcs12Bundle bundle = PkiPkcs12.create()
 *     .certificate(leafCert)
 *     .privateKey(leafKey)
 *     .chain(intermediate, root)
 *     .password("changeit")
 *     .build();
 *
 * bundle.saveTo(Path.of("keystore.p12"));
 * }</pre>
 */
public final class Pkcs12Builder {

    private static final String DEFAULT_ALIAS = "1";

    private X509Certificate certificate;
    private PrivateKey privateKey;
    private final List<X509Certificate> chainAboveLeaf = new ArrayList<>();
    private String alias = DEFAULT_ALIAS;
    private String password;

    Pkcs12Builder() {
        // Package-private: use PkiPkcs12.create().
    }

    /** Sets the leaf (primary) certificate. */
    public Pkcs12Builder certificate(X509Certificate certificate) {
        this.certificate = Objects.requireNonNull(certificate, "certificate");
        return this;
    }

    /**
     * Sets the private key for the leaf certificate. Leave unset for a
     * trust-only bundle (certificate entry without a key).
     */
    public Pkcs12Builder privateKey(PrivateKey privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        return this;
    }

    /**
     * Adds intermediate and root certificates above the leaf, in chain order.
     * Multiple calls accumulate.
     */
    public Pkcs12Builder chain(X509Certificate... chain) {
        Objects.requireNonNull(chain, "chain");
        for (X509Certificate c : chain) {
            chainAboveLeaf.add(Objects.requireNonNull(c, "chain element"));
        }
        return this;
    }

    /** Adds chain certificates from an existing list (copied). */
    public Pkcs12Builder chain(List<X509Certificate> chain) {
        Objects.requireNonNull(chain, "chain");
        for (X509Certificate c : chain) {
            chainAboveLeaf.add(Objects.requireNonNull(c, "chain element"));
        }
        return this;
    }

    /** Sets the keystore entry alias. Default is {@code "1"}. */
    public Pkcs12Builder alias(String alias) {
        this.alias = Objects.requireNonNull(alias, "alias");
        return this;
    }

    /** Sets the password protecting the PKCS#12 file and its key entry. */
    public Pkcs12Builder password(String password) {
        this.password = Objects.requireNonNull(password, "password");
        return this;
    }

    /**
     * Builds the bundle.
     *
     * @throws IllegalStateException if required fields are missing.
     */
    public Pkcs12Bundle build() {
        if (certificate == null) {
            throw new IllegalStateException("certificate is required");
        }
        if (password == null) {
            throw new IllegalStateException("password is required");
        }

        List<X509Certificate> fullChain = new ArrayList<>(1 + chainAboveLeaf.size());
        fullChain.add(certificate);
        fullChain.addAll(chainAboveLeaf);

        char[] pwd = password.toCharArray();
        try {
            return new Pkcs12Bundle(certificate, privateKey, fullChain, alias, pwd);
        } finally {
            Arrays.fill(pwd, '\0');
        }
    }
}
