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

import io.github.kaplaukhd.easypki.PkiCertificates;
import io.github.kaplaukhd.easypki.TrustBundle;
import io.github.kaplaukhd.easypki.validation.ChainBuilder;
import io.github.kaplaukhd.easypki.validation.CertChain;
import io.github.kaplaukhd.easypki.validation.ValidationError;
import io.github.kaplaukhd.easypki.validation.ValidationResult;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/** Explicit-trust JSSE adaptation retaining connection-specific JCA constraints. */
final class TlsTrustManagers {
    private TlsTrustManagers() {}

    static X509ExtendedTrustManager create(TrustBundle trust, TlsPeerPolicy policy) {
        Objects.requireNonNull(trust, "trust");
        Objects.requireNonNull(policy, "policy");
        return new PeerTrustManager(trust, policy, delegate(trust));
    }

    private static X509ExtendedTrustManager delegate(TrustBundle trust) {
        X509ExtendedTrustManager delegate = null;
        if (!trust.getTrustAnchors().isEmpty()) {
            try {
                Set<TrustAnchor> anchors = new LinkedHashSet<>();
                for (X509Certificate certificate : trust.getTrustAnchors()) anchors.add(new TrustAnchor(certificate, null));
                PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, new X509CertSelector());
                // Only the selected policy controls revocation. Do not inherit JSSE's global toggle.
                parameters.setRevocationEnabled(false);
                parameters.setMaxPathLength(-1);
                TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
                factory.init(new CertPathTrustManagerParameters(parameters));
                for (TrustManager manager : factory.getTrustManagers()) {
                    if (manager instanceof X509ExtendedTrustManager extended) {
                        delegate = extended;
                        break;
                    }
                }
                if (delegate == null) throw new IllegalStateException("PKIX provider does not expose an extended X.509 trust manager");
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Cannot initialize explicit TLS trust", e);
            }
        }
        return delegate;
    }

    private static final class PeerTrustManager extends X509ExtendedTrustManager {
        private final TrustBundle trust;
        private final TlsPeerPolicy policy;
        private final X509ExtendedTrustManager delegate;
        private final ConcurrentMap<X509Certificate, X509ExtendedTrustManager> anchorDelegates = new ConcurrentHashMap<>();

        private record Prepared(X509Certificate[] chain, X509ExtendedTrustManager verifier) {}

        private PeerTrustManager(TrustBundle trust, TlsPeerPolicy policy, X509ExtendedTrustManager delegate) {
            this.trust = trust;
            this.policy = policy;
            this.delegate = delegate;
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            Prepared peer = prepare(chain, authType, false);
            peer.verifier().checkClientTrusted(peer.chain(), authType);
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            Prepared peer = prepare(chain, authType, false);
            peer.verifier().checkClientTrusted(peer.chain(), authType, socket);
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            Prepared peer = prepare(chain, authType, false);
            peer.verifier().checkClientTrusted(peer.chain(), authType, engine);
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("TLS server validation requires a socket or engine with a reference hostname");
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            Prepared peer = prepare(chain, authType, true);
            if (!(socket instanceof SSLSocket ssl)) throw new CertificateException("TLS server validation requires an SSLSocket");
            SSLSession session = ssl.getHandshakeSession();
            if (session == null) throw new CertificateException("TLS server validation requires an active handshake");
            TlsServerNames.requireMatch(peer.chain()[0], session.getPeerHost());
            peer.verifier().checkServerTrusted(peer.chain(), authType, socket);
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            Prepared peer = prepare(chain, authType, true);
            if (engine == null) throw new CertificateException("TLS server validation requires an SSLEngine with a reference hostname");
            TlsServerNames.requireMatch(peer.chain()[0], engine.getPeerHost());
            peer.verifier().checkServerTrusted(peer.chain(), authType, engine);
        }

        @Override public X509Certificate[] getAcceptedIssuers() {
            return trust.getTrustAnchors().toArray(X509Certificate[]::new);
        }

        private Prepared prepare(X509Certificate[] chain, String authType, boolean server) throws CertificateException {
            if (delegate == null) throw new CertificateException("No TLS trust anchors configured");
            if (chain == null || chain.length == 0 || authType == null || authType.isBlank()) {
                throw new CertificateException("TLS peer chain and authentication type are required");
            }
            X509Certificate[] peer = new X509Certificate[chain.length];
            for (int index = 0; index < chain.length; index++) {
                if (chain[index] == null) throw new CertificateException("TLS peer chain must not contain null");
                try {
                    peer[index] = PkiCertificates.fromDer(chain[index].getEncoded());
                } catch (IllegalArgumentException e) {
                    throw new CertificateException("Invalid TLS peer certificate", e);
                }
            }
            X509Certificate leaf = peer[0];
            leaf.checkValidity();
            if (leaf.hasUnsupportedCriticalExtension()) {
                throw new CertificateException("TLS peer has an unsupported critical extension");
            }
            if (leaf.getBasicConstraints() >= 0) throw new CertificateException("TLS peer must be an end-entity certificate");
            boolean[] usage = leaf.getKeyUsage();
            if (usage == null || usage.length == 0 || !usage[0]) {
                throw new CertificateException("TLS peer requires digitalSignature KeyUsage");
            }
            List<String> purposes = leaf.getExtendedKeyUsage();
            String required = server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2";
            if (purposes == null || !purposes.contains(required)) {
                throw new CertificateException("TLS peer lacks the required " + (server ? "serverAuth" : "clientAuth") + " ExtendedKeyUsage");
            }
            if (!policy.checkRevocation()) return new Prepared(peer, delegate);
            return prepareRevocationPath(peer);
        }

        private Prepared prepareRevocationPath(X509Certificate[] peer) throws CertificateException {
            try {
                CertChain path = ChainBuilder.of(peer[0]).intermediates(Arrays.asList(peer)).trustBundle(trust).build();
                for (X509Certificate issuer : path.getCertificates().subList(1, path.size())) {
                    boolean[] usage = issuer.getKeyUsage();
                    if (usage != null && (usage.length <= 6 || !usage[6])) {
                        throw new CertificateException("TLS CRL issuer KeyUsage does not permit cRLSign");
                    }
                }
                ValidationResult result = path.toValidator().crl(policy.crls()).validate();
                if (!result.isValid() || result.getWarnings().stream()
                        .anyMatch(warning -> warning.code() == ValidationError.Code.REVOCATION_UNKNOWN)) {
                    throw new CertificateException("TLS CRL revocation validation failed: "
                            + (result.isValid() ? "revocation evidence is missing for part of the path" : result.getErrors()));
                }
                // Bind connection-specific constraints to the same chain and anchor
                // whose revocation evidence was checked, rather than a different cross-sign path.
                X509ExtendedTrustManager verifier = anchorDelegates.computeIfAbsent(path.getRoot(),
                        anchor -> delegate(TrustBundle.of(anchor)));
                return new Prepared(path.getCertificates().toArray(X509Certificate[]::new), verifier);
            } catch (IllegalStateException | IllegalArgumentException e) {
                throw new CertificateException("Cannot validate the TLS revocation path", e);
            }
        }
    }
}
