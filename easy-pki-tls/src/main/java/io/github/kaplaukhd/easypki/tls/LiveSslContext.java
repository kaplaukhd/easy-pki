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
package io.github.kaplaukhd.easypki.tls;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.function.Supplier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/** Stable context façade; cryptographic callbacks always belong to one concrete generation. */
final class LiveSslContext extends SSLContext {
    static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
    LiveSslContext(Supplier<TlsSnapshot> snapshots) { super(new Spi(snapshots), TlsStores.PROVIDER, "TLS"); }
    private static final class Spi extends SSLContextSpi {
        private final Supplier<TlsSnapshot> snapshots;
        private final SSLSocketFactory clients;
        private final SSLServerSocketFactory servers;
        Spi(Supplier<TlsSnapshot> snapshots) {
            this.snapshots = snapshots;
            clients = new LiveSocketFactory(snapshots);
            servers = new LiveServerSocketFactory(snapshots);
        }
        @Override protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException {
            throw new KeyManagementException("Use reloadIdentity/reloadTrust/reload to update this TLS context");
        }
        @Override protected SSLSocketFactory engineGetSocketFactory() { return clients; }
        @Override protected SSLServerSocketFactory engineGetServerSocketFactory() { return servers; }
        @Override protected SSLEngine engineCreateSSLEngine() { return configure(snapshots.get().context().createSSLEngine()); }
        @Override protected SSLEngine engineCreateSSLEngine(String host, int port) { return configure(snapshots.get().context().createSSLEngine(host, port)); }
        private SSLEngine configure(SSLEngine engine) {
            engine.setUseClientMode(false);
            engine.setEnabledProtocols(PROTOCOLS.clone());
            engine.setNeedClientAuth(true);
            return engine;
        }
        @Override protected SSLSessionContext engineGetClientSessionContext() { return snapshots.get().context().getClientSessionContext(); }
        @Override protected SSLSessionContext engineGetServerSessionContext() { return snapshots.get().context().getServerSessionContext(); }
        @Override protected SSLParameters engineGetDefaultSSLParameters() {
            SSLParameters parameters = snapshots.get().context().getDefaultSSLParameters();
            parameters.setProtocols(PROTOCOLS.clone());
            parameters.setNeedClientAuth(true);
            return parameters;
        }
        @Override protected SSLParameters engineGetSupportedSSLParameters() { return snapshots.get().context().getSupportedSSLParameters(); }
    }
}
