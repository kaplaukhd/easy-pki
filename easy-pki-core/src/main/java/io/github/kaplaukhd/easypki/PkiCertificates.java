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
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Reading and writing X.509 certificates in PEM and DER formats.
 *
 * <p>All methods are static. Parse errors are reported as
 * {@link IllegalArgumentException}; I/O failures as {@link UncheckedIOException}.
 *
 * <h2>Examples</h2>
 * <pre>{@code
 * // Read
 * X509Certificate cert  = PkiCertificates.fromPem(pemString);
 * X509Certificate cert  = PkiCertificates.fromFile(Path.of("ca.crt"));
 * List<X509Certificate> chain = PkiCertificates.allFromFile(Path.of("chain.pem"));
 *
 * // Write
 * String pem = PkiCertificates.toPem(cert);
 * byte[] der = PkiCertificates.toDer(cert);
 * PkiCertificates.toFile(cert, Path.of("out.crt"));
 * }</pre>
 */
public final class PkiCertificates {

    private PkiCertificates() {
        // Utility class.
    }

    // ---------- Reading ----------

    /** Parses a single certificate from a PEM-encoded string. */
    public static X509Certificate fromPem(String pem) {
        Objects.requireNonNull(pem, "pem");
        return fromPem(new StringReader(pem));
    }

    /**
     * Parses a single certificate from a {@link Reader} providing PEM-encoded
     * data. The reader is closed by this method.
     */
    public static X509Certificate fromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new IllegalArgumentException("No PEM object found");
            }
            if (!(obj instanceof X509CertificateHolder holder)) {
                throw new IllegalArgumentException(
                        "Expected an X.509 certificate, got " + obj.getClass().getSimpleName());
            }
            return toCertificate(holder);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM certificate", e);
        }
    }

    /**
     * Parses a single certificate from a PEM-encoded {@link InputStream}
     * (UTF-8). The stream is closed by this method.
     */
    public static X509Certificate fromPem(InputStream in) {
        Objects.requireNonNull(in, "in");
        return fromPem(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    /** Reads a single certificate from a PEM file. */
    public static X509Certificate fromFile(Path path) {
        Objects.requireNonNull(path, "path");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return fromPem(reader);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    /** Parses a certificate from raw DER bytes. */
    public static X509Certificate fromDer(byte[] der) {
        Objects.requireNonNull(der, "der");
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Failed to parse DER certificate", e);
        }
    }

    /**
     * Parses every certificate from a PEM string (useful for chain bundles).
     * Non-certificate PEM blocks cause an {@link IllegalArgumentException}.
     */
    public static List<X509Certificate> allFromPem(String pem) {
        Objects.requireNonNull(pem, "pem");
        return allFromPem(new StringReader(pem));
    }

    /** Reads every certificate from a {@link Reader}. The reader is closed. */
    public static List<X509Certificate> allFromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        List<X509Certificate> out = new ArrayList<>();
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj;
            while ((obj = parser.readObject()) != null) {
                if (!(obj instanceof X509CertificateHolder holder)) {
                    throw new IllegalArgumentException(
                            "Expected only X.509 certificates, found "
                                    + obj.getClass().getSimpleName());
                }
                out.add(toCertificate(holder));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM chain", e);
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("No certificates found");
        }
        return out;
    }

    /** Reads every certificate from a PEM file (chain bundle). */
    public static List<X509Certificate> allFromFile(Path path) {
        Objects.requireNonNull(path, "path");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return allFromPem(reader);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    // ---------- Writing ----------

    /** Serialises a certificate to a PEM string. */
    public static String toPem(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        StringWriter sw = new StringWriter();
        writePem(sw, List.of(certificate));
        return sw.toString();
    }

    /** Serialises a chain of certificates to a single PEM string. */
    public static String toPem(Iterable<X509Certificate> chain) {
        Objects.requireNonNull(chain, "chain");
        StringWriter sw = new StringWriter();
        writePem(sw, chain);
        return sw.toString();
    }

    /** Returns the DER encoding of the certificate. */
    public static byte[] toDer(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        try {
            return certificate.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encode certificate", e);
        }
    }

    /** Writes a certificate to a file as PEM. Overwrites existing content. */
    public static void toFile(X509Certificate certificate, Path path) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(path, "path");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writePem(writer, List.of(certificate));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    /** Writes a chain to a file as a PEM bundle. */
    public static void toFile(Iterable<X509Certificate> chain, Path path) {
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(path, "path");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writePem(writer, chain);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    // ---------- internals ----------

    private static void writePem(Writer writer, Iterable<X509Certificate> certs) {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            for (X509Certificate cert : certs) {
                pemWriter.writeObject(cert);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PEM", e);
        }
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) {
        try {
            return CertificateBuildSupport.toX509Certificate(holder);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid certificate encoding", e);
        }
    }
}
