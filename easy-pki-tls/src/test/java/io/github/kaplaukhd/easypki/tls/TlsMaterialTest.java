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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.kaplaukhd.easypki.Curve;
import io.github.kaplaukhd.easypki.ExtendedKeyUsage;
import io.github.kaplaukhd.easypki.KeyUsage;
import io.github.kaplaukhd.easypki.PkiCertificate;
import io.github.kaplaukhd.easypki.PkiCertificates;
import io.github.kaplaukhd.easypki.PkiIdentity;
import io.github.kaplaukhd.easypki.PkiKeys;
import io.github.kaplaukhd.easypki.PkiSigner;
import io.github.kaplaukhd.easypki.TrustBundle;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class TlsMaterialTest {
    private static final int TIMEOUT = 5000;
    private static final Instant NOW = Instant.now();
    private static final KeyPair ROOT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair SERVER_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair CLIENT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair INTERMEDIATE_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT = PkiCertificate.rootCa().subject("CN=Material Root")
            .keyPair(ROOT_KEYS).pathLength(2).validFrom(NOW.minus(Duration.ofDays(3)))
            .validUntil(NOW.plus(Duration.ofDays(30))).build();
    private static final PkiIdentity ROOT_IDENTITY = PkiIdentity.of(ROOT, ROOT_KEYS.getPrivate());
    private static final X509Certificate SERVER = PkiCertificate.tlsServer().subject("CN=Material Server")
            .keyPair(SERVER_KEYS).issuer(ROOT_IDENTITY).validFrom(NOW.minus(Duration.ofHours(1)))
            .validUntil(NOW.plus(Duration.ofDays(1))).san(s -> s.dns("localhost").ip("127.0.0.1")).build();
    private static final X509Certificate CLIENT = PkiCertificate.tlsClient().subject("CN=Material Client")
            .keyPair(CLIENT_KEYS).issuer(ROOT_IDENTITY).validFrom(NOW.minus(Duration.ofHours(1)))
            .validUntil(NOW.plus(Duration.ofDays(1))).build();
    private static final TrustBundle TRUST = TrustBundle.of(ROOT);

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void opaqueEcHandlesSupportPossessionProofAndRealMutualTlsWithoutEncoding(String protocol) throws Exception {
        var serverKey = new OpaqueEcPrivateKey((ECPrivateKey) SERVER_KEYS.getPrivate());
        var clientKey = new OpaqueEcPrivateKey((ECPrivateKey) CLIENT_KEYS.getPrivate());
        var providers = Security.getProviders();
        SSLContext defaultContext = SSLContext.getDefault();
        var serverIdentity = PkiIdentity.of(SERVER, serverKey, ROOT);
        var clientIdentity = PkiIdentity.of(CLIENT, clientKey, ROOT);
        var server = context(serverIdentity);
        var client = context(clientIdentity);
        assertThat(server.getSnapshot().getKeyStore().getKey("identity", new char[0])).isSameAs(serverKey);
        assertThat(client.getSnapshot().getKeyStore().getKey("identity", new char[0])).isSameAs(clientKey);
        X509KeyManager manager = Arrays.stream(server.getSnapshot().getKeyManagers())
                .filter(X509KeyManager.class::isInstance).map(X509KeyManager.class::cast).findFirst().orElseThrow();
        String alias = manager.getServerAliases("EC", null)[0];
        assertThat(manager.getPrivateKey(alias)).isSameAs(serverKey);
        assertThat(manager.getCertificateChain(alias)).containsExactly(SERVER, ROOT);

        exchange(server, client, protocol, SERVER, CLIENT);
        assertThat(serverKey.encodingCalls.get()).isZero();
        assertThat(clientKey.encodingCalls.get()).isZero();
        assertThat(Security.getProviders()).containsExactly(providers);
        assertThat(SSLContext.getDefault()).isSameAs(defaultContext);
    }

    @ParameterizedTest
    @CsvSource({"RSA,TLSv1.2", "RSA,TLSv1.3", "Ed25519,TLSv1.2", "Ed25519,TLSv1.3"})
    void standardRsaAndEd25519IdentitiesSupportNativeMutualTls(String algorithm, String protocol) throws Exception {
        KeyPair serverKeys = algorithm.equals("RSA") ? PkiKeys.rsa(2048) : PkiKeys.ed25519();
        KeyPair clientKeys = algorithm.equals("RSA") ? PkiKeys.rsa(2048) : PkiKeys.ed25519();
        X509Certificate serverCertificate = PkiCertificate.tlsServer().subject("CN=" + algorithm + " Server")
                .keyPair(serverKeys).issuer(ROOT_IDENTITY).validFrom(NOW.minus(Duration.ofHours(1)))
                .validUntil(NOW.plus(Duration.ofDays(1))).san(s -> s.dns("localhost").ip("127.0.0.1")).build();
        X509Certificate clientCertificate = PkiCertificate.tlsClient().subject("CN=" + algorithm + " Client")
                .keyPair(clientKeys).issuer(ROOT_IDENTITY).validFrom(NOW.minus(Duration.ofHours(1)))
                .validUntil(NOW.plus(Duration.ofDays(1))).build();
        var server = context(PkiIdentity.of(serverCertificate, serverKeys.getPrivate(), ROOT));
        var client = context(PkiIdentity.of(clientCertificate, clientKeys.getPrivate(), ROOT));
        exchange(server, client, protocol, serverCertificate, clientCertificate);
    }

    @Test
    void snapshotStoresAreReadOnlyAndRetainOriginalKeyHandle() throws Exception {
        var opaque = new OpaqueEcPrivateKey((ECPrivateKey) SERVER_KEYS.getPrivate());
        var identity = PkiIdentity.of(SERVER, opaque, ROOT);
        var snapshot = context(identity).getSnapshot();
        KeyStore keys = snapshot.getKeyStore();
        KeyStore trust = snapshot.getTrustStore();
        assertThat(Collections.list(keys.aliases())).containsExactly("identity");
        assertThat(keys.isKeyEntry("identity")).isTrue();
        assertThat(keys.isCertificateEntry("identity")).isFalse();
        assertThat(keys.getKey("identity", new char[0])).isSameAs(opaque);
        Certificate[] originalChain = keys.getCertificateChain("identity");
        originalChain[0] = ROOT;
        assertThat(keys.getCertificateChain("identity")).containsExactly(SERVER, ROOT);
        assertThat(trust.size()).isEqualTo(1);
        String anchorAlias = Collections.list(trust.aliases()).get(0);
        assertThat(trust.isCertificateEntry(anchorAlias)).isTrue();
        assertThat(trust.getKey(anchorAlias, new char[0])).isNull();
        for (KeyStore store : Arrays.asList(keys, trust)) {
            String existing = Collections.list(store.aliases()).get(0);
            assertThatThrownBy(() -> store.deleteEntry(existing)).isInstanceOf(KeyStoreException.class);
            assertThatThrownBy(() -> store.setCertificateEntry("new", ROOT)).isInstanceOf(KeyStoreException.class);
            assertThatThrownBy(() -> store.setKeyEntry("new", opaque, new char[0], new Certificate[]{SERVER, ROOT}))
                    .isInstanceOf(KeyStoreException.class);
            assertThatThrownBy(() -> store.setKeyEntry("new", new byte[]{1, 2}, new Certificate[]{SERVER, ROOT}))
                    .isInstanceOf(KeyStoreException.class);
            assertThatThrownBy(() -> store.setEntry("new", new KeyStore.TrustedCertificateEntry(ROOT), null))
                    .isInstanceOf(KeyStoreException.class);
            var output = new ByteArrayOutputStream();
            assertThatThrownBy(() -> store.store(output, new char[0])).isInstanceOf(IOException.class);
            assertThat(output.size()).isZero();
            assertThatThrownBy(() -> store.load(new ByteArrayInputStream(new byte[]{1, 2}), new char[0]))
                    .isInstanceOf(IOException.class);
            assertThat(store.containsAlias(existing)).isTrue();
            assertThat(store.containsAlias("new")).isFalse();
        }
        assertThat(keys.getKey("identity", new char[0])).isSameAs(opaque);
        assertThat(keys.getCertificateChain("identity")).containsExactly(SERVER, ROOT);
        assertThat(opaque.encodingCalls.get()).isZero();
    }

    @Test
    void snapshotManagerArraysCannotBeModifiedThroughAccessors() {
        var snapshot = context(PkiIdentity.of(SERVER, SERVER_KEYS.getPrivate(), ROOT)).getSnapshot();
        var keys = snapshot.getKeyManagers();
        var trust = snapshot.getTrustManagers();
        assertThat(keys).isNotEmpty();
        assertThat(trust).isNotEmpty();
        keys[0] = null;
        trust[0] = null;
        assertThat(snapshot.getKeyManagers()).doesNotContainNull();
        assertThat(snapshot.getTrustManagers()).doesNotContainNull();
    }

    @Test
    void signerOnlyIdentityFailsBeforeAdditionalSigningOrContextPublication() {
        var calls = new AtomicInteger();
        var delegate = PkiSigner.jca(SERVER_KEYS.getPrivate());
        var signer = new PkiSigner() {
            @Override public String signatureAlgorithm() { return delegate.signatureAlgorithm(); }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException {
                calls.incrementAndGet();
                return delegate.sign(content);
            }
        };
        PkiIdentity identity = PkiIdentity.of(SERVER, signer, ROOT);
        assertThat(calls.get()).isEqualTo(1);
        assertThatThrownBy(() -> context(identity)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PrivateKey");
        assertThat(calls.get()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"non-ca-issuer", "issuer-without-key-cert-sign", "exhausted-root-path", "expired-issuer"})
    void invalidLocalChainIsRejectedWithoutPublishingAMixedReplacement(String invalid) {
        X509Certificate root = invalid.equals("exhausted-root-path")
                ? PkiCertificate.rootCa().subject("CN=Bounded Root").keyPair(ROOT_KEYS).pathLength(0)
                        .validFrom(NOW.minus(Duration.ofDays(3))).validUntil(NOW.plus(Duration.ofDays(30))).build()
                : ROOT;
        var issuerBuilder = PkiCertificate.signed().subject("CN=Material Issuer").keyPair(INTERMEDIATE_KEYS)
                .issuer(root, ROOT_KEYS.getPrivate()).isCA(!invalid.equals("non-ca-issuer"))
                .validFrom(NOW.minus(Duration.ofDays(2)))
                .validUntil(invalid.equals("expired-issuer") ? NOW.minus(Duration.ofDays(1)) : NOW.plus(Duration.ofDays(2)));
        issuerBuilder.keyUsage(invalid.equals("issuer-without-key-cert-sign")
                ? KeyUsage.DIGITAL_SIGNATURE : KeyUsage.KEY_CERT_SIGN);
        X509Certificate issuer = issuerBuilder.build();
        X509Certificate leaf = PkiCertificate.signed().subject("CN=Server Replacement").keyPair(SERVER_KEYS)
                .issuer(issuer, INTERMEDIATE_KEYS.getPrivate()).validFrom(NOW.minus(Duration.ofHours(1)))
                .validUntil(NOW.plus(Duration.ofHours(1))).keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER).san(s -> s.dns("localhost")).build();
        PkiIdentity malformed = PkiIdentity.of(leaf, SERVER_KEYS.getPrivate(), issuer, root);
        var live = context(PkiIdentity.of(SERVER, SERVER_KEYS.getPrivate(), ROOT));
        var original = live.getSnapshot();
        assertThatThrownBy(() -> live.reload(malformed, TrustBundle.of()))
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(live.getSnapshot()).isSameAs(original);
        assertThat(live.getSnapshot().getTrustBundle().getTrustAnchors()).containsExactly(ROOT);
        assertThat(live.getSnapshot().getIdentity().orElseThrow().getCertificate()).isEqualTo(SERVER);
        assertThat(live.getSnapshot().getGeneration()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"terminal-unknown", "leaf-unknown", "terminal-known"})
    void unsupportedCriticalExtensionsCannotHideAtTheLocalConsistencyBoundary(String location) throws Exception {
        boolean terminalCa = !location.equals("leaf-unknown");
        boolean recognizedByJca = location.equals("terminal-known");
        KeyPair keys = terminalCa ? ROOT_KEYS : SERVER_KEYS;
        var name = terminalCa ? ROOT.getSubjectX500Principal() : SERVER.getSubjectX500Principal();
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(701),
                Date.from(NOW.minus(Duration.ofHours(1))), Date.from(NOW.plus(Duration.ofDays(1))),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true,
                terminalCa ? new BasicConstraints(2) : new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(
                terminalCa ? org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                        | org.bouncycastle.asn1.x509.KeyUsage.cRLSign
                        : org.bouncycastle.asn1.x509.KeyUsage.digitalSignature));
        if (!terminalCa) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        }
        if (recognizedByJca) {
            builder.addExtension(Extension.subjectAlternativeName, true,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "ca.example.test")));
        } else {
            builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.42"), true, DERNull.INSTANCE);
        }
        X509Certificate unsupported = PkiCertificates.fromDer(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())).getEncoded());
        assertThat(unsupported.hasUnsupportedCriticalExtension()).isEqualTo(!recognizedByJca);
        PkiIdentity replacement = terminalCa ? PkiIdentity.of(SERVER, SERVER_KEYS.getPrivate(), unsupported)
                : PkiIdentity.of(unsupported, SERVER_KEYS.getPrivate());
        var live = context(PkiIdentity.of(SERVER, SERVER_KEYS.getPrivate(), ROOT));
        var original = live.getSnapshot();
        assertThatThrownBy(() -> live.reload(replacement, TrustBundle.of()))
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
        assertThat(live.getSnapshot()).isSameAs(original);
        assertThat(live.getSnapshot().getTrustBundle().getTrustAnchors()).containsExactly(ROOT);
    }

    @Test
    void contextFacadeCannotBeReinitializedAroundTheRotationBoundary() {
        var live = context(PkiIdentity.of(SERVER, SERVER_KEYS.getPrivate(), ROOT));
        var original = live.getSnapshot();
        var facade = live.getSslContext();
        assertThatThrownBy(() -> facade.init(null, null, null)).isInstanceOf(KeyManagementException.class);
        assertThat(live.getSnapshot()).isSameAs(original);
        assertThat(facade.createSSLEngine().getEnabledProtocols()).containsExactly("TLSv1.3", "TLSv1.2");
    }

    @Test
    void trustAndRevocationChoiceMustBothBeExplicit() {
        assertThatThrownBy(() -> PkiTls.builder().build()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiTls.builder().trust(TRUST).build()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> PkiTls.builder().peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build())
                .isInstanceOf(IllegalStateException.class);
        assertThatCode(() -> PkiTls.builder().trust(TrustBundle.of())
                .peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build()).doesNotThrowAnyException();
    }

    @Test
    void explicitEmptyTrustAndMissingIdentityDoNotLoadPlatformDefaults() throws Exception {
        var snapshot = PkiTls.builder().trust(TrustBundle.of())
                .peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build().getSnapshot();
        assertThat(snapshot.getIdentity()).isEmpty();
        assertThat(snapshot.getKeyManagers()).isEmpty();
        assertThat(snapshot.getKeyStore().size()).isZero();
        assertThat(snapshot.getTrustStore().size()).isZero();
        assertThat(snapshot.getTrustBundle().getTrustAnchors()).isEmpty();
        X509TrustManager trust = (X509TrustManager) snapshot.getTrustManagers()[0];
        assertThat(trust.getAcceptedIssuers()).isEmpty();
    }

    private static ReloadableTlsContext context(PkiIdentity identity) {
        return PkiTls.builder().identity(identity).trust(TRUST)
                .peerPolicy(TlsPeerPolicy.withoutRevocationChecks()).build();
    }

    private static void exchange(ReloadableTlsContext server, ReloadableTlsContext client, String protocol,
                                  X509Certificate serverCertificate, X509Certificate clientCertificate) throws Exception {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (SSLServerSocket listener = (SSLServerSocket) server.getSslContext().getServerSocketFactory()
                .createServerSocket(0, 10, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}))) {
            listener.setSoTimeout(TIMEOUT);
            listener.setEnabledProtocols(new String[]{protocol});
            Future<X509Certificate> accepted = worker.submit(() -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setSoTimeout(TIMEOUT);
                    socket.startHandshake();
                    int value = socket.getInputStream().read();
                    socket.getOutputStream().write(value);
                    socket.getOutputStream().flush();
                    return (X509Certificate) socket.getSession().getPeerCertificates()[0];
                }
            });
            try (Socket tcp = new Socket()) {
                tcp.connect(new InetSocketAddress(listener.getInetAddress(), listener.getLocalPort()), TIMEOUT);
                try (SSLSocket socket = (SSLSocket) client.getSslContext().getSocketFactory()
                        .createSocket(tcp, "localhost", listener.getLocalPort(), true)) {
                    socket.setSoTimeout(TIMEOUT);
                    socket.setEnabledProtocols(new String[]{protocol});
                    socket.startHandshake();
                    socket.getOutputStream().write(42);
                    socket.getOutputStream().flush();
                    assertThat(socket.getInputStream().read()).isEqualTo(42);
                    assertThat(socket.getSession().getPeerCertificates()[0]).isEqualTo(serverCertificate);
                    assertThat(socket.getSession().getProtocol()).isEqualTo(protocol);
                }
            }
            assertThat(accepted.get(TIMEOUT, TimeUnit.MILLISECONDS)).isEqualTo(clientCertificate);
        } finally {
            worker.shutdownNow();
            assertThat(worker.awaitTermination(TIMEOUT, TimeUnit.MILLISECONDS)).isTrue();
        }
    }

    /** SunEC can translate this interface through getS()/getParams(); encoding is deliberately unavailable. */
    private static final class OpaqueEcPrivateKey implements ECPrivateKey {
        private static final long serialVersionUID = 1L;
        private final ECPrivateKey delegate;
        private final AtomicInteger encodingCalls = new AtomicInteger();
        OpaqueEcPrivateKey(ECPrivateKey delegate) { this.delegate = delegate; }
        @Override public BigInteger getS() { return delegate.getS(); }
        @Override public ECParameterSpec getParams() { return delegate.getParams(); }
        @Override public String getAlgorithm() { return "EC"; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() {
            encodingCalls.incrementAndGet();
            throw new AssertionError("TLS must not request the private key encoding");
        }
    }
}
