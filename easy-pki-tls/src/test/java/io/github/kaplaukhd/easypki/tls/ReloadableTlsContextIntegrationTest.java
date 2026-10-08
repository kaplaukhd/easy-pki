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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiSigner;
import io.github.kaplaukhd.easypki.TrustBundle;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ReloadableTlsContextIntegrationTest {
    private static final int TIMEOUT = 5000;
    private static final Instant NOW = Instant.now();
    private static final Authority CA_A = authority("CA A");
    private static final Authority CA_B = authority("CA B");
    private static final PkiIdentity SERVER_A = identity("Server A", CA_A, true);
    private static final PkiIdentity SERVER_B = identity("Server B", CA_B, true);
    private static final PkiIdentity CLIENT_A = identity("Client A", CA_A, false);
    private static final PkiIdentity CLIENT_B = identity("Client B", CA_B, false);
    private static final TrustBundle TRUST_A = TrustBundle.of(CA_A.certificate());
    private static final TrustBundle TRUST_B = TrustBundle.of(CA_B.certificate());
    private static final TrustBundle TRUST_BOTH = TRUST_A.merge(TRUST_B);

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void realMutualTlsWorksWithIndependentLocalAndPeerAuthorities(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_B);
        var client = context(CLIENT_B, TRUST_A);
        try (var listener = new Listener(server, protocol)) {
            Exchange result = listener.exchange(client.getSslContext().getSocketFactory(), protocol);
            result.requireSuccess();
            assertThat(result.client().peer()).isEqualTo(SERVER_A.getCertificate());
            assertThat(result.server().peer()).isEqualTo(CLIENT_B.getCertificate());
            assertThat(listener.socket.getNeedClientAuth()).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void mutualTlsRejectsAnUnauthenticatedClient(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var anonymousClient = PkiTls.builder().trust(TRUST_A)
                .peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build();
        try (var listener = new Listener(server, protocol)) {
            listener.exchange(anonymousClient.getSslContext().getSocketFactory(), protocol).requireRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void realHandshakeRejectsWrongExpectedServerName(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        try (var listener = new Listener(server, protocol)) {
            Future<Side> accepted = listener.acceptOne();
            Side rejected;
            try (SSLSocket socket = connect(client.getSslContext().getSocketFactory(),
                    listener.port(), protocol, "wrong.example.test")) {
                rejected = useClient(socket);
            }
            new Exchange(rejected, accepted.get(TIMEOUT, TimeUnit.MILLISECONDS)).requireRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void cachedFactoriesAndAlreadyBoundListenerUseNewIdentity(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_BOTH);
        SSLSocketFactory cachedClientFactory = client.getSslContext().getSocketFactory();
        var facade = server.getSslContext();
        var serverFactory = facade.getServerSocketFactory();
        try (var listener = new Listener(server, protocol)) {
            Exchange before = listener.exchange(cachedClientFactory, protocol);
            before.requireSuccess();
            assertThat(before.client().peer()).isEqualTo(SERVER_A.getCertificate());
            server.reloadIdentity(SERVER_B);
            assertThat(server.getSslContext()).isSameAs(facade);
            assertThat(facade.getServerSocketFactory()).isSameAs(serverFactory);
            assertThat(client.getSslContext().getSocketFactory()).isSameAs(cachedClientFactory);
            Exchange after = listener.exchange(cachedClientFactory, protocol);
            after.requireSuccess();
            assertThat(after.client().peer()).isEqualTo(SERVER_B.getCertificate());
            assertThat(after.server().peer()).isEqualTo(CLIENT_A.getCertificate());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void removedServerTrustCannotBeRecoveredThroughCachedClientSessions(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        SSLSocketFactory cachedFactory = client.getSslContext().getSocketFactory();
        try (var listener = new Listener(server, protocol)) {
            Exchange first = listener.exchange(cachedFactory, protocol);
            Exchange warm = listener.exchange(cachedFactory, protocol);
            first.requireSuccess();
            warm.requireSuccess();
            if (protocol.equals("TLSv1.2")) {
                assertThat(warm.client().sessionId()).as("warm connection resumes the TLS 1.2 session")
                        .isEqualTo(first.client().sessionId());
            }
            client.reloadTrust(TrustBundle.of());
            listener.exchange(cachedFactory, protocol).requireRejected();
            client.reloadTrust(TRUST_A);
            listener.exchange(cachedFactory, protocol).requireSuccess();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void removedClientTrustRejectsOldSessionTicketsOnExistingListener(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        SSLSocketFactory factory = client.getSslContext().getSocketFactory();
        try (var listener = new Listener(server, protocol)) {
            listener.exchange(factory, protocol).requireSuccess();
            listener.exchange(factory, protocol).requireSuccess();
            server.reloadTrust(TrustBundle.of());
            listener.exchange(factory, protocol).requireRejected();
            server.reloadTrust(TRUST_A);
            listener.exchange(factory, protocol).requireSuccess();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void refreshedRevocationPolicyRejectsFreshConnectionsWithAWarmedSession(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        try (var listener = new Listener(server, protocol)) {
            SSLSocketFactory factory = client.getSslContext().getSocketFactory();
            listener.exchange(factory, protocol).requireSuccess();
            var revoked = io.github.kaplaukhd.easypki.validation.PkiCrl.issued()
                    .issuer(CA_A.certificate(), CA_A.keys().getPrivate())
                    .thisUpdate(Instant.now().minusSeconds(30)).nextUpdate(Duration.ofHours(1))
                    .revoke(CLIENT_A.getCertificate(), io.github.kaplaukhd.easypki.validation.RevocationReason.KEY_COMPROMISE)
                    .build();
            assertThat(server.reloadPeerPolicy(TlsPeerPolicy.withCrls(revoked)).getGeneration()).isEqualTo(1);
            listener.exchange(factory, protocol).requireRejected();
            server.reloadPeerPolicy(TlsPeerPolicy.withoutRevocationChecks());
            listener.exchange(factory, protocol).requireSuccess();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void establishedStreamRemainsUsableAfterBothSidesRemoveTrust(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        try (var listener = new Listener(server, protocol)) {
            Future<Void> serverWork = listener.workers.submit(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.socket.accept()) {
                    accepted.setSoTimeout(TIMEOUT);
                    accepted.startHandshake();
                    echo(accepted, 2);
                }
                return null;
            });
            try (SSLSocket socket = connect(client.getSslContext().getSocketFactory(), listener.port(), protocol)) {
                socket.startHandshake();
                roundTrip(socket, 11);
                server.reload(SERVER_B, TrustBundle.of());
                client.reloadTrust(TrustBundle.of());
                roundTrip(socket, 22);
                assertThat(socket.getSession().getPeerCertificates()[0]).isEqualTo(SERVER_A.getCertificate());
            }
            serverWork.get(TIMEOUT, TimeUnit.MILLISECONDS);
            listener.exchange(client.getSslContext().getSocketFactory(), protocol).requireRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void socketCreatedBeforeRotationKeepsItsGenerationUntilDelayedHandshake(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var client = context(CLIENT_A, TRUST_A);
        SSLSocketFactory factory = client.getSslContext().getSocketFactory();
        try (var listener = new Listener(server, protocol)) {
            Future<Side> accepted;
            Side result;
            try (SSLSocket delayed = (SSLSocket) factory.createSocket()) {
                delayed.setEnabledProtocols(new String[]{protocol});
                delayed.setSoTimeout(TIMEOUT);
                client.reloadTrust(TrustBundle.of());
                accepted = listener.acceptOne();
                delayed.connect(new InetSocketAddress(loopback(), listener.port()), TIMEOUT);
                result = useClient(delayed);
            }
            new Exchange(result, accepted.get(TIMEOUT, TimeUnit.MILLISECONDS)).requireSuccess();
            listener.exchange(factory, protocol).requireRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void delayedEnginesKeepIdentityAndTrustFromOneGeneration(String protocol) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var clientA = context(CLIENT_A, TRUST_BOTH);
        var clientB = context(CLIENT_B, TRUST_BOTH);
        SSLEngine oldAcceptA = serverEngine(server, protocol);
        SSLEngine oldRejectB = serverEngine(server, protocol);
        server.reload(SERVER_B, TRUST_B);
        SSLEngine a = clientEngine(clientA, protocol);
        handshake(a, oldAcceptA);
        assertThat(a.getSession().getPeerCertificates()[0]).isEqualTo(SERVER_A.getCertificate());
        assertThat(oldAcceptA.getSession().getPeerCertificates()[0]).isEqualTo(CLIENT_A.getCertificate());
        assertThatThrownBy(() -> handshake(clientEngine(clientB, protocol), oldRejectB))
                .isInstanceOf(SSLException.class);
        SSLEngine b = clientEngine(clientB, protocol);
        SSLEngine newAcceptB = serverEngine(server, protocol);
        handshake(b, newAcceptB);
        assertThat(b.getSession().getPeerCertificates()[0]).isEqualTo(SERVER_B.getCertificate());
        assertThat(newAcceptB.getSession().getPeerCertificates()[0]).isEqualTo(CLIENT_B.getCertificate());
        assertThatThrownBy(() -> handshake(clientEngine(clientA, protocol), serverEngine(server, protocol)))
                .isInstanceOf(SSLException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"expired", "ca", "wrong-purpose", "signer-only"})
    void rejectedIdentityRotationPreservesTheWorkingGeneration(String invalid) throws Exception {
        var server = context(SERVER_A, TRUST_A);
        var original = server.getSnapshot();
        PkiIdentity replacement = switch (invalid) {
            case "expired" -> rawIdentity("Expired", true);
            case "ca" -> CA_A.identity();
            case "wrong-purpose" -> rawIdentity("Wrong Purpose", false);
            default -> PkiIdentity.of(SERVER_A.getCertificate(),
                    PkiSigner.jca(SERVER_A.getPrivateKey().orElseThrow()), CA_A.certificate());
        };
        assertThatThrownBy(() -> server.reloadIdentity(replacement))
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(server.getSnapshot()).isSameAs(original);
        assertThat(original.getGeneration()).isZero();
        try (var listener = new Listener(server, "TLSv1.3")) {
            Exchange result = listener.exchange(context(CLIENT_A, TRUST_A).getSslContext().getSocketFactory(), "TLSv1.3");
            result.requireSuccess();
            assertThat(result.client().peer()).isEqualTo(SERVER_A.getCertificate());
        }
    }

    @Test
    void concurrentPartialUpdatesRetainBothChanges() throws Exception {
        var context = context(SERVER_A, TRUST_A);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        var start = new CountDownLatch(1);
        try {
            Future<?> identity = workers.submit(() -> { await(start); context.reloadIdentity(SERVER_B); });
            Future<?> trust = workers.submit(() -> { await(start); context.reloadTrust(TRUST_B); });
            start.countDown();
            identity.get(TIMEOUT, TimeUnit.MILLISECONDS);
            trust.get(TIMEOUT, TimeUnit.MILLISECONDS);
            var current = context.getSnapshot();
            assertThat(current.getGeneration()).isEqualTo(2);
            assertThat(current.getIdentity()).contains(SERVER_B);
            assertThat(current.getTrustBundle().getTrustAnchors()).containsExactly(CA_B.certificate());
        } finally {
            workers.shutdownNow();
            assertThat(workers.awaitTermination(TIMEOUT, TimeUnit.MILLISECONDS)).isTrue();
        }
    }

    @Test
    void readersNeverObserveMixedIdentityAndTrustDuringJointUpdates() throws Exception {
        var context = context(SERVER_A, TRUST_A);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        var start = new CountDownLatch(1);
        var finished = new AtomicBoolean();
        try {
            Future<?> writer = workers.submit(() -> {
                await(start);
                try {
                    for (int i = 0; i < 30; i++) {
                        context.reload(i % 2 == 0 ? SERVER_B : SERVER_A, i % 2 == 0 ? TRUST_B : TRUST_A);
                    }
                } finally {
                    finished.set(true);
                }
            });
            Future<?> reader = workers.submit(() -> {
                await(start);
                int observations = 0;
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TIMEOUT);
                do {
                    var snapshot = context.getSnapshot();
                    PkiIdentity identity = snapshot.getIdentity().orElseThrow();
                    assertThat(snapshot.getTrustBundle().getTrustAnchors()).containsExactly(
                            identity.getCertificate().equals(SERVER_A.getCertificate()) ? CA_A.certificate() : CA_B.certificate());
                    observations++;
                    if (System.nanoTime() > deadline) throw new AssertionError("Snapshot reader exceeded its deadline");
                } while (!finished.get() || observations < 100);
            });
            start.countDown();
            writer.get(TIMEOUT, TimeUnit.MILLISECONDS);
            reader.get(TIMEOUT, TimeUnit.MILLISECONDS);
            assertThat(context.getSnapshot().getGeneration()).isEqualTo(30);
        } finally {
            workers.shutdownNow();
            assertThat(workers.awaitTermination(TIMEOUT, TimeUnit.MILLISECONDS)).isTrue();
        }
    }

    private static ReloadableTlsContext context(PkiIdentity identity, TrustBundle trust) {
        return PkiTls.builder().identity(identity).trust(trust)
                .peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build();
    }

    private static PkiIdentity rawIdentity(String name, boolean expired) {
        KeyPair keys = PkiKeys.ec(Curve.P_256);
        var certificate = PkiCertificate.signed().subject("CN=" + name).keyPair(keys)
                .issuer(CA_A.certificate(), CA_A.keys().getPrivate())
                .validFrom(NOW.minus(Duration.ofDays(2)))
                .validUntil(expired ? NOW.minus(Duration.ofDays(1)) : NOW.plus(Duration.ofDays(1)))
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(expired ? ExtendedKeyUsage.TLS_SERVER : ExtendedKeyUsage.CODE_SIGNING)
                .san(s -> s.dns("localhost").ip("127.0.0.1")).build();
        return PkiIdentity.of(certificate, keys.getPrivate(), CA_A.certificate());
    }

    private static Authority authority(String name) {
        KeyPair keys = PkiKeys.ec(Curve.P_256);
        X509Certificate certificate = PkiCertificate.rootCa().subject("CN=" + name).keyPair(keys)
                .validFrom(NOW.minus(Duration.ofDays(3))).validUntil(NOW.plus(Duration.ofDays(30))).pathLength(2).build();
        return new Authority(keys, certificate, PkiIdentity.of(certificate, keys.getPrivate()));
    }

    private static PkiIdentity identity(String name, Authority authority, boolean server) {
        KeyPair keys = PkiKeys.ec(Curve.P_256);
        var builder = (server ? PkiCertificate.tlsServer() : PkiCertificate.tlsClient())
                .subject("CN=" + name).keyPair(keys).issuer(authority.identity())
                .validFrom(NOW.minus(Duration.ofHours(1))).validUntil(NOW.plus(Duration.ofDays(2)));
        if (server) builder.san(s -> s.dns("localhost").ip("127.0.0.1"));
        return PkiIdentity.of(builder.build(), keys.getPrivate(), authority.certificate());
    }

    private static InetAddress loopback() throws IOException {
        return InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
    }

    private static SSLSocket connect(SSLSocketFactory factory, int port, String protocol) throws IOException {
        return connect(factory, port, protocol, "localhost");
    }

    private static SSLSocket connect(SSLSocketFactory factory, int port, String protocol, String expectedHost)
            throws IOException {
        Socket tcp = new Socket();
        try {
            tcp.connect(new InetSocketAddress(loopback(), port), TIMEOUT);
            SSLSocket socket = (SSLSocket) factory.createSocket(tcp, expectedHost, port, true);
            socket.setSoTimeout(TIMEOUT);
            socket.setEnabledProtocols(new String[]{protocol});
            return socket;
        } catch (IOException | RuntimeException e) {
            tcp.close();
            throw e;
        }
    }

    private static Side useClient(SSLSocket socket) {
        try {
            socket.startHandshake();
            roundTrip(socket, 73);
            return new Side((X509Certificate) socket.getSession().getPeerCertificates()[0],
                    socket.getSession().getId(), null);
        } catch (IOException failure) {
            return new Side(null, null, failure);
        }
    }

    private static void roundTrip(SSLSocket socket, int value) throws IOException {
        socket.getOutputStream().write(value);
        socket.getOutputStream().flush();
        assertThat(socket.getInputStream().read()).isEqualTo(value);
    }

    private static void echo(SSLSocket socket, int messages) throws IOException {
        for (int i = 0; i < messages; i++) {
            int value = socket.getInputStream().read();
            if (value < 0) throw new IOException("Peer closed before application exchange");
            socket.getOutputStream().write(value);
            socket.getOutputStream().flush();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(TIMEOUT, TimeUnit.MILLISECONDS)) throw new AssertionError("Worker start timed out");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    private static SSLEngine clientEngine(ReloadableTlsContext context, String protocol) {
        SSLEngine engine = context.getSslContext().createSSLEngine("localhost", 443);
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[]{protocol});
        return engine;
    }

    private static SSLEngine serverEngine(ReloadableTlsContext context, String protocol) {
        SSLEngine engine = context.getSslContext().createSSLEngine();
        assertThat(engine.getUseClientMode()).isFalse();
        assertThat(engine.getNeedClientAuth()).isTrue();
        engine.setEnabledProtocols(new String[]{protocol});
        return engine;
    }

    /** Exchanges real TLS records with finite iterations, including delegated JCA tasks. */
    private static void handshake(SSLEngine client, SSLEngine server) throws SSLException {
        ByteBuffer toClient = ByteBuffer.allocate(128 * 1024);
        ByteBuffer toServer = ByteBuffer.allocate(128 * 1024);
        ByteBuffer plain = ByteBuffer.allocate(128 * 1024);
        client.beginHandshake();
        server.beginHandshake();
        for (int step = 0; step < 256; step++) {
            tasks(client);
            tasks(server);
            wrap(client, toServer);
            unwrap(server, toServer, plain);
            tasks(server);
            wrap(server, toClient);
            unwrap(client, toClient, plain);
            if (client.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                    && server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;
        }
        throw new AssertionError("SSLEngine handshake exceeded 256 record-processing steps");
    }

    private static void tasks(SSLEngine engine) {
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) task.run();
        }
    }

    private static void wrap(SSLEngine engine, ByteBuffer output) throws SSLException {
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            SSLEngineResult result = engine.wrap(ByteBuffer.allocate(0), output);
            if (result.getStatus() == SSLEngineResult.Status.CLOSED) throw new SSLException("Engine closed during handshake");
            assertThat(result.getStatus()).isNotEqualTo(SSLEngineResult.Status.BUFFER_OVERFLOW);
        }
    }

    private static void unwrap(SSLEngine engine, ByteBuffer input, ByteBuffer plain) throws SSLException {
        input.flip();
        try {
            if (input.hasRemaining() && engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_TASK
                    && engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                plain.clear();
                SSLEngineResult result = engine.unwrap(input, plain);
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) throw new SSLException("Engine rejected handshake");
                assertThat(result.getStatus()).isNotEqualTo(SSLEngineResult.Status.BUFFER_OVERFLOW);
            }
        } finally {
            input.compact();
        }
    }

    private static final class Listener implements AutoCloseable {
        private final SSLServerSocket socket;
        private final ExecutorService workers = Executors.newCachedThreadPool();

        Listener(ReloadableTlsContext context, String protocol) throws IOException {
            socket = (SSLServerSocket) context.getSslContext().getServerSocketFactory()
                    .createServerSocket(0, 20, loopback());
            socket.setSoTimeout(TIMEOUT);
            socket.setEnabledProtocols(new String[]{protocol});
        }

        int port() { return socket.getLocalPort(); }

        Future<Side> acceptOne() {
            return workers.submit(() -> {
                try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                    accepted.setSoTimeout(TIMEOUT);
                    accepted.startHandshake();
                    X509Certificate peer = (X509Certificate) accepted.getSession().getPeerCertificates()[0];
                    echo(accepted, 1);
                    return new Side(peer, accepted.getSession().getId(), null);
                } catch (IOException failure) {
                    return new Side(null, null, failure);
                }
            });
        }

        Exchange exchange(SSLSocketFactory factory, String protocol) throws Exception {
            Future<Side> accepted = acceptOne();
            Side client;
            try (SSLSocket connection = connect(factory, port(), protocol)) {
                client = useClient(connection);
            }
            return new Exchange(client, accepted.get(TIMEOUT, TimeUnit.MILLISECONDS));
        }

        @Override public void close() throws IOException {
            socket.close();
            workers.shutdownNow();
            try {
                if (!workers.awaitTermination(TIMEOUT, TimeUnit.MILLISECONDS)) throw new AssertionError("TLS worker did not stop");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while stopping TLS worker", e);
            }
        }
    }

    private record Authority(KeyPair keys, X509Certificate certificate, PkiIdentity identity) {}
    private record Side(X509Certificate peer, byte[] sessionId, IOException failure) {}
    private record Exchange(Side client, Side server) {
        void requireSuccess() {
            assertThat(client.failure()).as("client handshake and authenticated echo").isNull();
            assertThat(server.failure()).as("server handshake and authenticated echo").isNull();
        }
        void requireRejected() {
            assertThat(Arrays.asList(client.failure(), server.failure()))
                    .as("a TLS authentication failure, not a timeout or test harness failure")
                    .anyMatch(SSLException.class::isInstance);
        }
    }
}
