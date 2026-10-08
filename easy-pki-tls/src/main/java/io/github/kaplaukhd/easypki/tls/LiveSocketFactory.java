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

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.function.Supplier;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class LiveSocketFactory extends SSLSocketFactory {
    private final Supplier<TlsSnapshot> snapshots;
    LiveSocketFactory(Supplier<TlsSnapshot> snapshots) { this.snapshots = snapshots; }
    private SSLSocketFactory factory() { return snapshots.get().context().getSocketFactory(); }
    @Override public String[] getDefaultCipherSuites() { return factory().getDefaultCipherSuites(); }
    @Override public String[] getSupportedCipherSuites() { return factory().getSupportedCipherSuites(); }
    @Override public Socket createSocket() throws IOException { return configure(factory().createSocket()); }
    @Override public Socket createSocket(String host, int port) throws IOException { return configure(factory().createSocket(host, port)); }
    @Override public Socket createSocket(String host, int port, InetAddress local, int localPort) throws IOException {
        return configure(factory().createSocket(host, port, local, localPort));
    }
    @Override public Socket createSocket(InetAddress address, int port) throws IOException {
        return createSocket(address.getHostAddress(), port);
    }
    @Override public Socket createSocket(InetAddress address, int port, InetAddress local, int localPort) throws IOException {
        return createSocket(address.getHostAddress(), port, local, localPort);
    }
    @Override public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return configure(factory().createSocket(socket, host, port, autoClose));
    }
    @Override public Socket createSocket(Socket socket, InputStream consumed, boolean autoClose) throws IOException {
        return configure(factory().createSocket(socket, consumed, autoClose));
    }
    private static Socket configure(Socket socket) {
        SSLSocket tls = (SSLSocket) socket;
        tls.setEnabledProtocols(LiveSslContext.PROTOCOLS.clone());
        if (!tls.getUseClientMode()) tls.setNeedClientAuth(true);
        return tls;
    }
}
