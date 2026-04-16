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
package io.github.kaplaukhd.easypki.test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiKeys;

/**
 * Fluent builder for {@link TestPki}. Obtain via {@link TestPki#create()}.
 *
 * <p>Defaults:
 * <ul>
 *   <li>Root CA: RSA 2048, 10-year validity.</li>
 *   <li>Intermediate CA (when configured): RSA 2048, 5-year validity.</li>
 *   <li>Default DNs: {@code CN=Test Root CA} and {@code CN=Test Issuing CA}.</li>
 * </ul>
 */
public final class TestPkiBuilder {

    private String rootSubject = "CN=Test Root CA";
    private Duration rootValidity = Duration.ofDays(3650);
    private KeyPair rootKeys;

    private boolean withIntermediate;
    private String intermediateSubject = "CN=Test Issuing CA";
    private Duration intermediateValidity = Duration.ofDays(1825);
    private KeyPair intermediateKeys;

    TestPkiBuilder() {
        // Package-private — use TestPki.create().
    }

    /** Configures the root CA subject DN. */
    public TestPkiBuilder withRootCa(String subjectDn) {
        this.rootSubject = Objects.requireNonNull(subjectDn, "subjectDn");
        return this;
    }

    /** Configures the root CA subject DN and validity. */
    public TestPkiBuilder withRootCa(String subjectDn, Duration validity) {
        this.rootSubject = Objects.requireNonNull(subjectDn, "subjectDn");
        this.rootValidity = Objects.requireNonNull(validity, "validity");
        return this;
    }

    /** Overrides the key pair used for the root CA. Default is a fresh RSA 2048. */
    public TestPkiBuilder withRootKeys(KeyPair keys) {
        this.rootKeys = Objects.requireNonNull(keys, "keys");
        return this;
    }

    /** Adds an intermediate CA signed by the root, using the default DN. */
    public TestPkiBuilder withIntermediateCa() {
        this.withIntermediate = true;
        return this;
    }

    /** Adds an intermediate CA with a custom subject DN. */
    public TestPkiBuilder withIntermediateCa(String subjectDn) {
        this.withIntermediate = true;
        this.intermediateSubject = Objects.requireNonNull(subjectDn, "subjectDn");
        return this;
    }

    /** Adds an intermediate CA with a custom subject DN and validity. */
    public TestPkiBuilder withIntermediateCa(String subjectDn, Duration validity) {
        this.withIntermediate = true;
        this.intermediateSubject = Objects.requireNonNull(subjectDn, "subjectDn");
        this.intermediateValidity = Objects.requireNonNull(validity, "validity");
        return this;
    }

    /** Overrides the key pair used for the intermediate CA. */
    public TestPkiBuilder withIntermediateKeys(KeyPair keys) {
        this.intermediateKeys = Objects.requireNonNull(keys, "keys");
        this.withIntermediate = true;
        return this;
    }

    /** Builds the hierarchy. */
    public TestPki build() {
        KeyPair rk = (rootKeys != null) ? rootKeys : PkiKeys.rsa(2048);
        X509Certificate root = PkiCertificate.selfSigned()
                .subject(rootSubject)
                .keyPair(rk)
                .validFor(rootValidity)
                .isCA(true)
                .pathLength(withIntermediate ? 1 : 0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .build();

        KeyPair ik = null;
        X509Certificate intermediate = null;
        if (withIntermediate) {
            ik = (intermediateKeys != null) ? intermediateKeys : PkiKeys.rsa(2048);
            intermediate = PkiCertificate.signed()
                    .subject(intermediateSubject)
                    .publicKey(ik.getPublic())
                    .issuer(root, rk.getPrivate())
                    .validFor(intermediateValidity)
                    .pathLength(0)
                    .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                    .build();
        }

        return new TestPki(rk, root, ik, intermediate);
    }
}
