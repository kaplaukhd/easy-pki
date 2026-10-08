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

import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Path;

/**
 * Creation and parsing of PKCS#10 certificate signing requests.
 *
 * <p>Parsing preserves requested values without granting them authority.
 * Call {@link CsrRequest#requireValidSignature()} to verify a parsed request;
 * creation verifies the newly produced signature before returning it.
 */
public final class PkiCsr {
    private PkiCsr() {
        // Utility class.
    }

    /** Starts a request builder with no subject, signing key or requested extensions. */
    public static CsrBuilder create() {
        return new CsrBuilder();
    }

    /** Starts certificate issuance with explicit CA authorization and proof-of-possession checks. */
    public static CsrCertificateBuilder issue(CsrRequest request, CsrIssuancePolicy policy) {
        return new CsrCertificateBuilder(request, policy);
    }

    /** Parses exactly one PEM request without verifying its signature. */
    public static CsrRequest fromPem(String pem) {
        return CsrRequest.fromPem(pem);
    }

    /** Parses exactly one PEM request, closing the reader, without verifying its signature. */
    public static CsrRequest fromPem(Reader reader) {
        return CsrRequest.fromPem(reader);
    }

    /** Parses exactly one UTF-8 PEM request, closing the stream, without verifying its signature. */
    public static CsrRequest fromPem(InputStream input) {
        return CsrRequest.fromPem(input);
    }

    /** Parses exactly one DER request without verifying its signature. */
    public static CsrRequest fromDer(byte[] der) {
        return CsrRequest.fromDer(der);
    }

    /** Reads exactly one PEM or DER request from a file without verifying its signature. */
    public static CsrRequest fromFile(Path path) {
        return CsrRequest.fromFile(path);
    }
}
