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
import java.util.Arrays;
import java.util.function.Function;

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
 *
 * <p>Encrypted output defaults to PBKDF2-HMAC-SHA-256 with 600,000 iterations;
 * {@link PemEncryptionOptions} makes the policy explicit. Password arrays are
 * copied for each synchronous operation and those copies are cleared in a
 * finally block. Caller arrays are never changed and remain the caller's
 * responsibility. String overloads remain for compatibility, but Strings
 * cannot be erased. Provider/JVM-internal copies cannot be guaranteed erased.
 * Neither this class nor the options retain passwords after an operation.
 */
public final class PkiPrivateKeys {

    private static final Provider BC = new BouncyCastleProvider();

    private PkiPrivateKeys() {
        // Utility class.
    }

    // ---------- Reading ----------

    /** Reads unencrypted PEM from a String; supplied streams/readers are closed. */
    public static PrivateKey fromPem(String pem) {
        Objects.requireNonNull(pem, "pem");
        return fromReader(new StringReader(pem), null);
    }

    /** Reads encrypted PEM using a compatibility String password. */
    public static PrivateKey fromPem(String pem, String password) {
        return withPassword(password, chars -> fromPem(pem, chars));
    }

    /** Reads encrypted PEM with a temporary password copy; the caller array is unchanged. */
    public static PrivateKey fromPem(String pem, char[] password) {
        Objects.requireNonNull(pem, "pem");
        Objects.requireNonNull(password, "password");
        return fromReader(new StringReader(pem), password);
    }

    /** Reads unencrypted PEM from a Reader; supplied streams/readers are closed. */
    public static PrivateKey fromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        return fromReader(reader, null);
    }

    /** Reads encrypted PEM using a compatibility String password. */
    public static PrivateKey fromPem(Reader reader, String password) {
        return withPassword(password, chars -> fromPem(reader, chars));
    }

    /** Reads encrypted PEM with a temporary password copy; the caller array is unchanged. */
    public static PrivateKey fromPem(Reader reader, char[] password) {
        Objects.requireNonNull(reader, "reader");
        Objects.requireNonNull(password, "password");
        return fromReader(reader, password);
    }

    /** Reads unencrypted PEM from a InputStream; supplied streams/readers are closed. */
    public static PrivateKey fromPem(InputStream in) {
        Objects.requireNonNull(in, "in");
        return fromReader(new InputStreamReader(in, StandardCharsets.UTF_8), null);
    }

    /** Reads encrypted PEM using a compatibility String password. */
    public static PrivateKey fromPem(InputStream in, String password) {
        return withPassword(password, chars -> fromPem(in, chars));
    }

    /** Reads encrypted PEM with a temporary password copy; the caller array is unchanged. */
    public static PrivateKey fromPem(InputStream in, char[] password) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(password, "password");
        return fromReader(new InputStreamReader(in, StandardCharsets.UTF_8), password);
    }

    /** Reads an unencrypted PEM file. */
    public static PrivateKey fromFile(Path path) {
        return readFile(path, null);
    }

    /** Reads an encrypted PEM file with a compatibility String password. */
    public static PrivateKey fromFile(Path path, String password) {
        return withPassword(password, chars -> fromFile(path, chars));
    }

    /** Reads an encrypted PEM file; the caller password array is unchanged. */
    public static PrivateKey fromFile(Path path, char[] password) {
        Objects.requireNonNull(password, "password");
        return readFile(path, password);
    }

    private static PrivateKey readFile(Path path, char[] password) {
        Objects.requireNonNull(path, "path");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return fromReader(reader, password);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file " + path, e);
        }
    }

    // ---------- Writing ----------

    /** Writes unencrypted PKCS#8 PEM to a String. */
    public static String toPem(PrivateKey key) {
        Objects.requireNonNull(key, "key");
        StringWriter sw = new StringWriter();
        writeUnencrypted(sw, key);
        return sw.toString();
    }

    /** Writes encrypted PKCS#8 PEM with the default policy and a String password. */
    public static String toPem(PrivateKey key, String password) {
        return withPassword(password, chars -> toPem(key, chars));
    }

    /** Writes encrypted PKCS#8 PEM with the default policy; caller password is unchanged. */
    public static String toPem(PrivateKey key, char[] password) {
        return toPem(key, password, PemEncryptionOptions.defaults());
    }

    /** Writes encrypted PKCS#8 PEM using explicit policy and a String password. */
    public static String toPem(PrivateKey key, String password, PemEncryptionOptions options) {
        return withPassword(password, chars -> toPem(key, chars, options));
    }

    /** Writes encrypted PKCS#8 PEM using explicit policy; no password is retained. */
    public static String toPem(PrivateKey key, char[] password, PemEncryptionOptions options) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(options, "options");
        StringWriter sw = new StringWriter();
        writeEncrypted(sw, key, password, options);
        return sw.toString();
    }

    /** Writes unencrypted PKCS#8 PEM to a file. */
    public static void toFile(PrivateKey key, Path path) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(path, "path");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writeUnencrypted(writer, key);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    /** Writes encrypted PEM to a file using the default policy and a String password. */
    public static void toFile(PrivateKey key, Path path, String password) {
        toFile(key, path, password, PemEncryptionOptions.defaults());
    }

    /** Writes encrypted PEM to a file using the default policy; caller password is unchanged. */
    public static void toFile(PrivateKey key, Path path, char[] password) {
        toFile(key, path, password, PemEncryptionOptions.defaults());
    }

    /** Writes encrypted PEM to a file using explicit policy and a String password. */
    public static void toFile(PrivateKey key, Path path, String password, PemEncryptionOptions options) {
        withPassword(password, chars -> { toFile(key, path, chars, options); return null; });
    }

    /** Writes encrypted PEM to a file using explicit policy; no password is retained. */
    public static void toFile(PrivateKey key, Path path, char[] password, PemEncryptionOptions options) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(options, "options");
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writeEncrypted(writer, key, password, options);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write file " + path, e);
        }
    }

    // ---------- internals ----------

    private static PrivateKey fromReader(Reader reader, char[] password) {
        char[] secret = password == null ? null : password.clone();
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
                requireNonNullPassword(secret);
                PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder()
                        .setProvider(BC)
                        .build(secret);
                PEMKeyPair decrypted = encrypted.decryptKeyPair(provider);
                return converter.getKeyPair(decrypted).getPrivate();
            }
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                requireNonNullPassword(secret);
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BC)
                        .build(secret);
                return converter.getPrivateKey(encrypted.decryptPrivateKeyInfo(provider));
            }
            throw new IllegalArgumentException(
                    "Unsupported PEM object: " + obj.getClass().getSimpleName());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM private key", e);
        } catch (PKCSException | OperatorCreationException e) {
            throw new IllegalArgumentException(
                    "Failed to decrypt private key (wrong password?)", e);
        } finally {
            if (secret != null) Arrays.fill(secret, '\0');
        }
    }

    private static void requireNonNullPassword(char[] password) {
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

    private static void writeEncrypted(Writer writer, PrivateKey key, char[] password,
                                       PemEncryptionOptions options) {
        char[] secret = password.clone();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                    PKCS8Generator.AES_256_CBC)
                    .setProvider(BC)
                    .setPRF(options.prf().identifier())
                    .setIterationCount(options.iterations())
                    .setPassword(secret)
                    .build();
            pemWriter.writeObject(new JcaPKCS8Generator(key, encryptor));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write PEM private key", e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Failed to configure PKCS#8 encryptor", e);
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    private static <T> T withPassword(String password, Function<char[], T> operation) {
        char[] chars = Objects.requireNonNull(password, "password").toCharArray();
        try {
            return operation.apply(chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }
}
