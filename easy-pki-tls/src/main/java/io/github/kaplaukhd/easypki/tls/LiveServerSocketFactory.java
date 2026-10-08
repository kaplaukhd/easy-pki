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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.function.Supplier;
import javax.net.ssl.SSLServerSocketFactory;

final class LiveServerSocketFactory extends SSLServerSocketFactory {
    private final Supplier<TlsSnapshot> snapshots;
    LiveServerSocketFactory(Supplier<TlsSnapshot> snapshots) { this.snapshots = snapshots; }
    @Override public String[] getDefaultCipherSuites() { return snapshots.get().context().getServerSocketFactory().getDefaultCipherSuites(); }
    @Override public String[] getSupportedCipherSuites() { return snapshots.get().context().getServerSocketFactory().getSupportedCipherSuites(); }
    @Override public ServerSocket createServerSocket() throws IOException { return new LiveServerSocket(snapshots); }
    @Override public ServerSocket createServerSocket(int port) throws IOException { return createServerSocket(port, 50, null); }
    @Override public ServerSocket createServerSocket(int port, int backlog) throws IOException { return createServerSocket(port, backlog, null); }
    @Override public ServerSocket createServerSocket(int port, int backlog, InetAddress address) throws IOException {
        ServerSocket server = createServerSocket();
        try {
            server.bind(new InetSocketAddress(address, port), backlog);
            return server;
        } catch (IOException | RuntimeException e) {
            try { server.close(); } catch (IOException closeFailure) { e.addSuppressed(closeFailure); }
            throw e;
        }
    }
}
