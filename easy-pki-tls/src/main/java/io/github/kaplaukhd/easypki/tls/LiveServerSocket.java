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
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.nio.channels.ServerSocketChannel;
import java.util.Set;
import java.util.function.Supplier;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** TCP listener with SSL configuration; each accepted socket uses a complete current generation. */
final class LiveServerSocket extends SSLServerSocket {
    private final Supplier<TlsSnapshot> snapshots;
    private final ServerSocket tcp = new ServerSocket();
    // An unbound native SSLServerSocket provides full JSSE SSLParameters validation and copies.
    private final SSLServerSocket settings;

    LiveServerSocket(Supplier<TlsSnapshot> snapshots) throws IOException {
        this.snapshots = snapshots;
        settings = (SSLServerSocket) snapshots.get().context().getServerSocketFactory().createServerSocket();
        settings.setEnabledProtocols(LiveSslContext.PROTOCOLS.clone());
        settings.setNeedClientAuth(true);
    }
    @Override public Socket accept() throws IOException {
        Socket accepted = tcp.accept();
        try {
            TlsSnapshot snapshot = snapshots.get();
            SSLSocket tls = (SSLSocket) snapshot.context().getSocketFactory().createSocket(
                    accepted, accepted.getInetAddress().getHostAddress(), accepted.getPort(), true);
            synchronized (settings) {
                tls.setUseClientMode(settings.getUseClientMode());
                tls.setSSLParameters(settings.getSSLParameters());
                tls.setEnableSessionCreation(settings.getEnableSessionCreation());
            }
            return tls;
        } catch (IOException | RuntimeException e) {
            try { accepted.close(); } catch (IOException closeFailure) { e.addSuppressed(closeFailure); }
            throw e;
        }
    }
    @Override public String[] getEnabledCipherSuites() { synchronized (settings) { return settings.getEnabledCipherSuites(); } }
    @Override public void setEnabledCipherSuites(String[] suites) { synchronized (settings) { settings.setEnabledCipherSuites(suites); } }
    @Override public String[] getSupportedCipherSuites() { synchronized (settings) { return settings.getSupportedCipherSuites(); } }
    @Override public String[] getSupportedProtocols() { synchronized (settings) { return settings.getSupportedProtocols(); } }
    @Override public String[] getEnabledProtocols() { synchronized (settings) { return settings.getEnabledProtocols(); } }
    @Override public void setEnabledProtocols(String[] protocols) { synchronized (settings) { settings.setEnabledProtocols(protocols); } }
    @Override public void setNeedClientAuth(boolean need) { synchronized (settings) { settings.setNeedClientAuth(need); } }
    @Override public boolean getNeedClientAuth() { synchronized (settings) { return settings.getNeedClientAuth(); } }
    @Override public void setWantClientAuth(boolean want) { synchronized (settings) { settings.setWantClientAuth(want); } }
    @Override public boolean getWantClientAuth() { synchronized (settings) { return settings.getWantClientAuth(); } }
    @Override public void setUseClientMode(boolean mode) { synchronized (settings) { settings.setUseClientMode(mode); } }
    @Override public boolean getUseClientMode() { synchronized (settings) { return settings.getUseClientMode(); } }
    @Override public void setEnableSessionCreation(boolean enabled) { synchronized (settings) { settings.setEnableSessionCreation(enabled); } }
    @Override public boolean getEnableSessionCreation() { synchronized (settings) { return settings.getEnableSessionCreation(); } }
    @Override public SSLParameters getSSLParameters() { synchronized (settings) { return settings.getSSLParameters(); } }
    @Override public void setSSLParameters(SSLParameters parameters) { synchronized (settings) { settings.setSSLParameters(parameters); } }
    @Override public void bind(SocketAddress address) throws IOException { tcp.bind(address); }
    @Override public void bind(SocketAddress address, int backlog) throws IOException { tcp.bind(address, backlog); }
    @Override public InetAddress getInetAddress() { return tcp.getInetAddress(); }
    @Override public int getLocalPort() { return tcp.getLocalPort(); }
    @Override public SocketAddress getLocalSocketAddress() { return tcp.getLocalSocketAddress(); }
    @Override public ServerSocketChannel getChannel() { return tcp.getChannel(); }
    @Override public boolean isBound() { return tcp.isBound(); }
    @Override public boolean isClosed() { return tcp.isClosed(); }
    @Override public void close() throws IOException {
        try { tcp.close(); } finally {
            try { settings.close(); } finally { super.close(); }
        }
    }
    @Override public void setSoTimeout(int timeout) throws SocketException { tcp.setSoTimeout(timeout); }
    @Override public int getSoTimeout() throws IOException { return tcp.getSoTimeout(); }
    @Override public void setReuseAddress(boolean enabled) throws SocketException { tcp.setReuseAddress(enabled); }
    @Override public boolean getReuseAddress() throws SocketException { return tcp.getReuseAddress(); }
    @Override public void setReceiveBufferSize(int size) throws SocketException { tcp.setReceiveBufferSize(size); }
    @Override public int getReceiveBufferSize() throws SocketException { return tcp.getReceiveBufferSize(); }
    @Override public <T> ServerSocket setOption(SocketOption<T> option, T value) throws IOException { tcp.setOption(option, value); return this; }
    @Override public <T> T getOption(SocketOption<T> option) throws IOException { return tcp.getOption(option); }
    @Override public Set<SocketOption<?>> supportedOptions() { return tcp.supportedOptions(); }
    @Override public String toString() { return "RotatingTLS[" + tcp + "]"; }
}
