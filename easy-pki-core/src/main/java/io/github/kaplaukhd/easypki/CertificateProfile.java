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

/**
 * Opt-in certificate issuance policies. Raw signed/self-signed builders remain
 * available without a profile. Profiles add mandatory role extensions and reject
 * conflicting configuration before requesting a certificate signature.
 * Issued profiles require a PkiIdentity and check every supplied CA's known
 * authority, validity and path constraints; they do not establish PKIX trust.
 */
public enum CertificateProfile {
    /** Self-signed CA; critical CA BasicConstraints and keyCertSign/cRLSign; optional path length. */
    ROOT_CA,
    /** Issued CA; the CA extension set with default pathLength=0 and issuer preflight checks. */
    INTERMEDIATE_CA,
    /** Signing TLS server; DNS/IP SAN required, serverAuth only, digitalSignature. */
    TLS_SERVER,
    /** Signing TLS client; explicit subject or SAN identity, clientAuth only, digitalSignature. */
    TLS_CLIENT;

    boolean isCa() { return this == ROOT_CA || this == INTERMEDIATE_CA; }
    boolean isTls() { return !isCa(); }
}
