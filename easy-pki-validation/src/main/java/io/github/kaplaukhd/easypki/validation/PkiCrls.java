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
package io.github.kaplaukhd.easypki.validation;

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
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Objects;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * PEM and DER I/O for X.509 Certificate Revocation Lists.
 */
public final class PkiCrls {

    private PkiCrls() {
        // Utility class.
    }

    // ---------- Reading ----------

    /** Parses a CRL from a PEM string. */
    public static X509CRL fromPem(String pem) {
        Objects.requireNonNull(pem, "pem");
        return fromPem(new StringReader(pem));
    }

    /** Parses a CRL from a {@link Reader} (closed by this method). */
    public static X509CRL fromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new IllegalArgumentException("No PEM object found");
            }
            if (!(obj instanceof X509CRLHolder holder)) {
                throw new IllegalArgumentException(
                        "Expected an X.509 CRL, got " + obj.getClass().getSimpleName());
            }
            try {
                return CrlBuildSupport.toX509Crl(holder);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException("Invalid CRL encoding", e);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM CRL", e);
        }
    }

    /** Parses a CRL from a PEM-encoded {@link InputStream} (UTF-8). */
    public static X509CRL fromPem(InputStream in) {
        Objects.requireNonNull(in, "in");
        return fromPem(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    /** Parses a CRL from raw DER bytes. */
    public static X509CRL fromDer(byte[] der) {
        Objects.requireNonNull(der, "der");
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to parse DER CRL", e);
        }
    }

    /** Reads a CRL from a file (auto-detects PEM vs DER by first byte). */
    public static X509CRL fromFile(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            byte[] bytes = Files.readAllBytes(path);
            // DER starts with 0x30 (SEQUENCE); PEM starts with '-' ('-----BEGIN').
            if (bytes.length > 0 && bytes[0] == 0x30) {
                return fromDer(bytes);
            }
            return fromPem(new String(bytes, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    // ---------- Writing ----------

    public static String toPem(X509CRL crl) {
        Objects.requireNonNull(crl, "crl");
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(crl);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PEM CRL", e);
        }
        return sw.toString();
    }

    public static byte[] toDer(X509CRL crl) {
        Objects.requireNonNull(crl, "crl");
        try {
            return crl.getEncoded();
        } catch (CRLException e) {
            throw new IllegalStateException("Failed to encode CRL", e);
        }
    }

    /** Writes a CRL as PEM. Overwrites existing content. */
    public static void toFile(X509CRL crl, Path path) {
        Objects.requireNonNull(crl, "crl");
        Objects.requireNonNull(path, "path");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8);
             JcaPEMWriter pem = new JcaPEMWriter(writer)) {
            pem.writeObject(crl);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }
}
