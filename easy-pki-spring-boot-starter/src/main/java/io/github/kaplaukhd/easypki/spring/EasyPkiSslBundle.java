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
package io.github.kaplaukhd.easypki.spring;

import io.github.kaplaukhd.easypki.tls.ReloadableTlsContext;
import io.github.kaplaukhd.easypki.tls.TlsSnapshot;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.boot.ssl.SslStoreBundle;

/**
 * A Spring SSL bundle backed by one reloadable TLS context.
 *
 * <p>{@link #createSslContext()} returns the stable live context. New TLS engines
 * and sockets capture a complete material generation. Stores and manager bundles
 * expose coherent snapshots at the time their getter is called; consumers that
 * retain those snapshots do not gain live reload. The starter integrates the
 * live context with JSSE Tomcat and Spring's supported RestClient path.
 *
 * <p>Update the original {@link ReloadableTlsContext}, not Spring's bundle
 * registry. This class does not register providers, export private keys, watch
 * files, close the supplied context or change the process-wide default SSL context.
 */
public final class EasyPkiSslBundle implements SslBundle {
    private static final Provider MANAGERS_PROVIDER = new Provider(
            "EasyPkiSslManagers", "1.0", "Read-only easy-pki manager snapshots") {
        private static final long serialVersionUID = 1L;
    };
    private final ReloadableTlsContext context;

    private EasyPkiSslBundle(ReloadableTlsContext context) {
        this.context = Objects.requireNonNull(context, "context");
    }

    /** Adapts an application-owned TLS context without changing its peer policy. */
    public static EasyPkiSslBundle of(ReloadableTlsContext context) {
        return new EasyPkiSslBundle(context);
    }

    /** Returns both stores from one material generation, without serializing key material. */
    @Override public SslStoreBundle getStores() {
        TlsSnapshot snapshot = context.getSnapshot();
        return SslStoreBundle.of(snapshot.getKeyStore(), null, snapshot.getTrustStore());
    }

    /** The TLS key manager owns alias selection. */
    @Override public SslBundleKey getKey() { return SslBundleKey.NONE; }

    /** Uses the consumer's JSSE protocol and cipher defaults. */
    @Override public SslOptions getOptions() { return SslOptions.NONE; }

    /** Returns the JSSE TLS protocol family. */
    @Override public String getProtocol() { return DEFAULT_PROTOCOL; }

    /** Returns key and trust managers captured together from the current generation. */
    @Override public SslManagerBundle getManagers() {
        TlsSnapshot snapshot = context.getSnapshot();
        return SslManagerBundle.of(new SnapshotKeyManagerFactory(snapshot.getKeyManagers()),
                new SnapshotTrustManagerFactory(snapshot.getTrustManagers()));
    }

    /** Returns the live context, including subsequent successful material updates. */
    @Override public SSLContext createSslContext() { return context.getSslContext(); }

    TlsSnapshot snapshot() { return context.getSnapshot(); }

    private static final class SnapshotKeyManagerFactory extends KeyManagerFactory {
        SnapshotKeyManagerFactory(KeyManager[] managers) {
            super(new KeyManagerFactorySpi() {
                @Override protected void engineInit(KeyStore store, char[] password) throws KeyStoreException {
                    throw new KeyStoreException("SSL manager snapshots cannot be reinitialized");
                }
                @Override protected void engineInit(ManagerFactoryParameters parameters)
                        throws InvalidAlgorithmParameterException {
                    throw new InvalidAlgorithmParameterException("SSL manager snapshots cannot be reinitialized");
                }
                @Override protected KeyManager[] engineGetKeyManagers() { return managers.clone(); }
            }, MANAGERS_PROVIDER, "easy-pki-snapshot");
        }
    }

    private static final class SnapshotTrustManagerFactory extends TrustManagerFactory {
        SnapshotTrustManagerFactory(TrustManager[] managers) {
            super(new TrustManagerFactorySpi() {
                @Override protected void engineInit(KeyStore store) throws KeyStoreException {
                    throw new KeyStoreException("SSL manager snapshots cannot be reinitialized");
                }
                @Override protected void engineInit(ManagerFactoryParameters parameters)
                        throws InvalidAlgorithmParameterException {
                    throw new InvalidAlgorithmParameterException("SSL manager snapshots cannot be reinitialized");
                }
                @Override protected TrustManager[] engineGetTrustManagers() { return managers.clone(); }
            }, MANAGERS_PROVIDER, "easy-pki-snapshot");
        }
    }
}
