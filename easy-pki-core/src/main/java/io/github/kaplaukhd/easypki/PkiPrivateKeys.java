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
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Objects;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

/**
 * Reading and writing private keys in PEM format.
 *
 * <p>Supported input formats:
 * <ul>
 *   <li>Unencrypted PKCS#8 ({@code -----BEGIN PRIVATE KEY-----})</li>
 *   <li>Encrypted PKCS#8 ({@code -----BEGIN ENCRYPTED PRIVATE KEY-----})</li>
 *   <li>Traditional OpenSSL PKCS#1 RSA
 *       ({@code -----BEGIN RSA PRIVATE KEY-----}), optionally with the
 *       legacy {@code Proc-Type: 4,ENCRYPTED} password protection</li>
 *   <li>Traditional OpenSSL EC ({@code -----BEGIN EC PRIVATE KEY-----})</li>
 * </ul>
 *
 * <p>All output is modern PKCS#8 (PBES2 + AES-256-CBC when a password is
 * supplied). Parse errors and password failures are reported as
 * {@link IllegalArgumentException}.
 */
public final class PkiPrivateKeys {

    private static final Provider BC = new BouncyCastleProvider();

    private PkiPrivateKeys() {
        // Utility class.
    }

    // ---------- Reading ----------

    /** Parses an unencrypted private key from a PEM string. */
    public static PrivateKey fromPem(String pem) {
        Objects.requireNonNull(pem, "pem");
        return fromReader(new StringReader(pem), null);
    }

    /** Parses an encrypted private key from a PEM string using the given password. */
    public static PrivateKey fromPem(String pem, String password) {
        Objects.requireNonNull(pem, "pem");
        Objects.requireNonNull(password, "password");
        return fromReader(new StringReader(pem), password);
    }

    /** Parses an unencrypted private key from a {@link Reader} (closed by this method). */
    public static PrivateKey fromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        return fromReader(reader, null);
    }

    /** Parses an encrypted private key from a {@link Reader} (closed by this method). */
    public static PrivateKey fromPem(Reader reader, String password) {
        Objects.requireNonNull(reader, "reader");
        Objects.requireNonNull(password, "password");
        return fromReader(reader, password);
    }

    /** Parses an unencrypted private key from a PEM-encoded {@link InputStream}. */
    public static PrivateKey fromPem(InputStream in) {
        Objects.requireNonNull(in, "in");
        return fromReader(new InputStreamReader(in, StandardCharsets.UTF_8), null);
    }

    /** Parses an encrypted private key from a PEM-encoded {@link InputStream}. */
    public static PrivateKey fromPem(InputStream in, String password) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(password, "password");
        return fromReader(new InputStreamReader(in, StandardCharsets.UTF_8), password);
    }

    /** Reads an unencrypted private key from a PEM file. */
    public static PrivateKey fromFile(Path path) {
        Objects.requireNonNull(path, "path");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return fromReader(reader, null);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    /** Reads an encrypted private key from a PEM file. */
    public static PrivateKey fromFile(Path path, String password) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(password, "password");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return fromReader(reader, password);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    // ---------- Writing ----------

    /**
     * Serialises the key as unencrypted PKCS#8 PEM
     * ({@code -----BEGIN PRIVATE KEY-----}).
     */
    public static String toPem(PrivateKey key) {
        Objects.requireNonNull(key, "key");
        StringWriter sw = new StringWriter();
        writeUnencrypted(sw, key);
        return sw.toString();
    }

    /**
     * Serialises the key as encrypted PKCS#8 PEM using PBES2 + AES-256-CBC
     * ({@code -----BEGIN ENCRYPTED PRIVATE KEY-----}).
     */
    public static String toPem(PrivateKey key, String password) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(password, "password");
        StringWriter sw = new StringWriter();
        writeEncrypted(sw, key, password);
        return sw.toString();
    }

    /** Writes the key to a file as unencrypted PKCS#8 PEM. */
    public static void toFile(PrivateKey key, Path path) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(path, "path");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writeUnencrypted(writer, key);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    /** Writes the key to a file as encrypted PKCS#8 PEM (PBES2 + AES-256-CBC). */
    public static void toFile(PrivateKey key, Path path, String password) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(password, "password");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writeEncrypted(writer, key, password);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    // ---------- internals ----------

    private static PrivateKey fromReader(Reader reader, String password) {
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new IllegalArgumentException("No PEM object found");
            }
            // Do not set the BC provider on the converter: the JDK default
            // names EC keys as "EC" (as in PkiKeys), while BC names them "ECDSA".
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (obj instanceof PEMKeyPair pemKeyPair) {
                return converter.getKeyPair(pemKeyPair).getPrivate();
            }
            if (obj instanceof PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            }
            if (obj instanceof PEMEncryptedKeyPair encrypted) {
                requireNonNullPassword(password);
                PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder()
                        .setProvider(BC)
                        .build(password.toCharArray());
                PEMKeyPair decrypted = encrypted.decryptKeyPair(provider);
                return converter.getKeyPair(decrypted).getPrivate();
            }
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                requireNonNullPassword(password);
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BC)
                        .build(password.toCharArray());
                return converter.getPrivateKey(encrypted.decryptPrivateKeyInfo(provider));
            }
            throw new IllegalArgumentException(
                    "Unsupported PEM object: " + obj.getClass().getSimpleName());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM private key", e);
        } catch (PKCSException | OperatorCreationException e) {
            throw new IllegalArgumentException(
                    "Failed to decrypt private key (wrong password?)", e);
        }
    }

    private static void requireNonNullPassword(String password) {
        if (password == null) {
            throw new IllegalArgumentException(
                    "The PEM is encrypted but no password was provided");
        }
    }

    private static void writeUnencrypted(Writer writer, PrivateKey key) {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(new JcaPKCS8Generator(key, null));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PEM private key", e);
        }
    }

    private static void writeEncrypted(Writer writer, PrivateKey key, String password) {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                    PKCS8Generator.AES_256_CBC)
                    .setProvider(BC)
                    .setPassword(password.toCharArray())
                    .build();
            pemWriter.writeObject(new JcaPKCS8Generator(key, encryptor));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PEM private key", e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Failed to configure PKCS#8 encryptor", e);
        }
    }
}
