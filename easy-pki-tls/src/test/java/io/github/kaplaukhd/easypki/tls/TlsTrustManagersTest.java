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
import io.github.kaplaukhd.easypki.TrustBundle;
import io.github.kaplaukhd.easypki.validation.PkiCrl;
import io.github.kaplaukhd.easypki.validation.RevocationReason;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;

class TlsTrustManagersTest {
    private static final Instant NOW = Instant.now();
    private static final KeyPair ROOT_KEYS = PkiKeys.ec(Curve.P_256);
    private static final KeyPair LEAF_KEYS = PkiKeys.ec(Curve.P_256);
    private static final X509Certificate ROOT = PkiCertificate.rootCa().subject("CN=TLS Trust Root")
            .keyPair(ROOT_KEYS).validFrom(NOW.minusSeconds(60)).validFor(Duration.ofDays(2)).pathLength(2).build();
    private static final PkiIdentity ROOT_IDENTITY = PkiIdentity.of(ROOT, ROOT_KEYS.getPrivate());
    private static final X509Certificate CLIENT = PkiCertificate.tlsClient().subject("CN=TLS Client")
            .keyPair(LEAF_KEYS).issuer(ROOT_IDENTITY).validFrom(NOW.minusSeconds(30)).validFor(Duration.ofDays(1)).build();
    private static final X509Certificate SERVER = PkiCertificate.tlsServer().subject("CN=TLS Server")
            .keyPair(LEAF_KEYS).issuer(ROOT_IDENTITY).validFrom(NOW.minusSeconds(30)).validFor(Duration.ofDays(1))
            .san(names -> names.dns("server.example.test")).build();

    @Test
    void validatesClientPkixAndRoleWithoutChangingGlobalProviders() throws Exception {
        var providers = Security.getProviders();
        X509ExtendedTrustManager manager = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withoutRevocationChecks());
        manager.checkClientTrusted(new X509Certificate[] {CLIENT, ROOT}, "EC");
        manager.checkClientTrusted(new X509Certificate[] {CLIENT}, "EC");
        manager.checkClientTrusted(new X509Certificate[] {CLIENT}, "EC", (Socket) null);
        manager.checkClientTrusted(new X509Certificate[] {CLIENT}, "EC", (SSLEngine) null);
        assertThat(manager.getAcceptedIssuers()).containsExactly(ROOT);
        X509Certificate[] exported = manager.getAcceptedIssuers();
        exported[0] = CLIENT;
        assertThat(manager.getAcceptedIssuers()).containsExactly(ROOT);
        assertThat(Security.getProviders()).containsExactly(providers);
    }

    @Test
    void acceptsExplicitLeafTrustButStillChecksLeafValidityAndPurpose() throws Exception {
        manager(TrustBundle.of(CLIENT), TlsPeerPolicy.withoutRevocationChecks())
                .checkClientTrusted(new X509Certificate[] {CLIENT}, "EC");
        X509Certificate expired = rawClient(NOW.minus(Duration.ofDays(2)), Duration.ofDays(1),
                false, new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE}, new ExtendedKeyUsage[] {ExtendedKeyUsage.TLS_CLIENT});
        assertRejected(manager(TrustBundle.of(expired), TlsPeerPolicy.withoutRevocationChecks()), expired);
        assertRejected(manager(TrustBundle.of(SERVER), TlsPeerPolicy.withoutRevocationChecks()), SERVER);
    }

    @Test
    void emptyOrUnrelatedTrustNeverUsesTheHostDefaultTrustStore() {
        assertRejected(manager(TrustBundle.of(), TlsPeerPolicy.withoutRevocationChecks()), CLIENT);
        X509Certificate other = PkiCertificate.rootCa().subject("CN=Other Root").keyPair(LEAF_KEYS)
                .validFor(Duration.ofDays(1)).build();
        assertRejected(manager(TrustBundle.of(other), TlsPeerPolicy.withoutRevocationChecks()), CLIENT);
        assertThat(manager(TrustBundle.of(), TlsPeerPolicy.withoutRevocationChecks()).getAcceptedIssuers()).isEmpty();
    }

    @Test
    void anExplicitlyTrustedLeafStillRejectsUnsupportedCriticalExtensions() throws Exception {
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(CLIENT);
        builder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.55555.42"),
                true, org.bouncycastle.asn1.DERNull.INSTANCE);
        X509Certificate unsupported = io.github.kaplaukhd.easypki.PkiCertificates.fromDer(builder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                        .build(ROOT_KEYS.getPrivate())).getEncoded());
        unsupported.verify(ROOT.getPublicKey());
        assertThat(unsupported.hasUnsupportedCriticalExtension()).isTrue();
        assertRejected(manager(TrustBundle.of(unsupported), TlsPeerPolicy.withoutRevocationChecks()), unsupported);
    }

    @Test
    void rejectsMissingWrongPurposeMissingDigitalSignatureAndCaPeer() {
        var manager = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withoutRevocationChecks());
        assertRejected(manager, SERVER);
        assertRejected(manager, rawClient(NOW.minusSeconds(30), Duration.ofHours(1), false,
                new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE}, new ExtendedKeyUsage[0]));
        assertRejected(manager, rawClient(NOW.minusSeconds(30), Duration.ofHours(1), false,
                new KeyUsage[0], new ExtendedKeyUsage[] {ExtendedKeyUsage.TLS_CLIENT}));
        assertRejected(manager, rawClient(NOW.minusSeconds(30), Duration.ofHours(1), false,
                new KeyUsage[] {KeyUsage.KEY_ENCIPHERMENT}, new ExtendedKeyUsage[] {ExtendedKeyUsage.TLS_CLIENT}));
        assertRejected(manager, rawClient(NOW.minusSeconds(30), Duration.ofHours(1), true,
                new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_CERT_SIGN}, new ExtendedKeyUsage[] {ExtendedKeyUsage.TLS_CLIENT}));
        assertRejected(manager, rawClient(NOW.plus(Duration.ofDays(1)), Duration.ofHours(1), false,
                new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE}, new ExtendedKeyUsage[] {ExtendedKeyUsage.TLS_CLIENT}));
    }

    @Test
    void rejectsMissingReferenceContextForEveryServerOverload() {
        var manager = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withoutRevocationChecks());
        X509Certificate[] chain = {SERVER, ROOT};
        assertThatThrownBy(() -> manager.checkServerTrusted(chain, "EC")).isInstanceOf(CertificateException.class);
        assertThatThrownBy(() -> manager.checkServerTrusted(chain, "EC", (Socket) null)).isInstanceOf(CertificateException.class);
        assertThatThrownBy(() -> manager.checkServerTrusted(chain, "EC", (SSLEngine) null)).isInstanceOf(CertificateException.class);
    }

    @Test
    void rejectsMalformedPeerArguments() {
        var manager = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withoutRevocationChecks());
        assertThatThrownBy(() -> manager.checkClientTrusted(null, "EC")).isInstanceOf(CertificateException.class);
        assertThatThrownBy(() -> manager.checkClientTrusted(new X509Certificate[0], "EC")).isInstanceOf(CertificateException.class);
        assertThatThrownBy(() -> manager.checkClientTrusted(new X509Certificate[] {null}, "EC")).isInstanceOf(CertificateException.class);
        assertThatThrownBy(() -> manager.checkClientTrusted(new X509Certificate[] {CLIENT}, " ")).isInstanceOf(CertificateException.class);
    }

    @Test
    void offlineCrlPolicyAcceptsGoodAndRejectsRevokedExpiredAndWrongIssuerEvidence() throws Exception {
        X509CRL good = crl(ROOT, ROOT_KEYS, false);
        X509CRL revoked = crl(ROOT, ROOT_KEYS, true);
        manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(good))
                .checkClientTrusted(new X509Certificate[] {CLIENT, ROOT}, "EC");
        assertRejected(manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(revoked)), CLIENT);
        X509CRL expired = PkiCrl.issued().issuer(ROOT, ROOT_KEYS.getPrivate())
                .thisUpdate(NOW.minus(Duration.ofDays(2))).nextUpdate(NOW.minus(Duration.ofDays(1))).build();
        assertRejected(manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(expired)), CLIENT);
        X509CRL badSignature = PkiCrl.issued().issuer(ROOT, LEAF_KEYS.getPrivate())
                .thisUpdate(NOW.minusSeconds(30)).nextUpdate(Duration.ofHours(1)).build();
        assertRejected(manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(badSignature)), CLIENT);
        X509Certificate other = PkiCertificate.rootCa().subject("CN=Other CRL Root").keyPair(LEAF_KEYS)
                .validFor(Duration.ofDays(1)).build();
        assertRejected(manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(crl(other, LEAF_KEYS, false))), CLIENT);
    }

    @Test
    void missingIntermediateRevocationEvidenceIsAFailureAndExplicitIntermediateAnchorsWork() throws Exception {
        KeyPair intermediateKeys = PkiKeys.ec(Curve.P_256);
        X509Certificate intermediate = PkiCertificate.intermediateCa().subject("CN=TLS Intermediate")
                .keyPair(intermediateKeys).issuer(ROOT_IDENTITY).validFrom(NOW.minusSeconds(30)).validFor(Duration.ofDays(1)).build();
        X509Certificate client = PkiCertificate.tlsClient().subject("CN=Intermediate Client").keyPair(LEAF_KEYS)
                .issuer(PkiIdentity.of(intermediate, intermediateKeys.getPrivate(), ROOT))
                .validFrom(NOW.minusSeconds(10)).validFor(Duration.ofHours(1)).build();
        X509CRL intermediateCrl = crl(intermediate, intermediateKeys, false);
        X509Certificate[] chain = {client, intermediate, ROOT};
        var incomplete = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(intermediateCrl));
        assertThatThrownBy(() -> incomplete.checkClientTrusted(chain, "EC"))
                .isInstanceOf(CertificateException.class).hasMessageContaining("revocation");
        manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(intermediateCrl, crl(ROOT, ROOT_KEYS, false)))
                .checkClientTrusted(chain, "EC");
        manager(TrustBundle.of(intermediate), TlsPeerPolicy.withCrls(intermediateCrl))
                .checkClientTrusted(new X509Certificate[] {client}, "EC");
    }

    @Test
    void offlineCrlPolicyRejectsAnIssuerWhoseKeyUsageDoesNotAuthorizeCrlSigning() throws Exception {
        X509Certificate restrictedRoot = PkiCertificate.selfSigned().subject("CN=Cert signing only")
                .keyPair(ROOT_KEYS).isCA(true).keyUsage(KeyUsage.KEY_CERT_SIGN)
                .validFrom(NOW.minusSeconds(60)).validFor(Duration.ofDays(2)).build();
        X509Certificate client = PkiCertificate.signed().subject("CN=Client of restricted CA")
                .keyPair(LEAF_KEYS).issuer(restrictedRoot, ROOT_KEYS.getPrivate())
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE).extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT)
                .validFrom(NOW.minusSeconds(30)).validFor(Duration.ofDays(1)).build();
        manager(TrustBundle.of(restrictedRoot), TlsPeerPolicy.withoutRevocationChecks())
                .checkClientTrusted(new X509Certificate[] {client}, "EC");
        var manager = manager(TrustBundle.of(restrictedRoot), TlsPeerPolicy.withCrls(crl(restrictedRoot, ROOT_KEYS, false)));
        assertThatThrownBy(() -> manager.checkClientTrusted(new X509Certificate[] {client}, "EC"))
                .isInstanceOf(CertificateException.class).hasMessageContaining("cRLSign");
    }

    @Test
    void policyCopiesCrlCollectionAndRequiresFiniteFreshness() throws Exception {
        List<X509CRL> crls = new ArrayList<>(List.of(crl(ROOT, ROOT_KEYS, false)));
        TlsPeerPolicy policy = TlsPeerPolicy.withCrls(crls);
        crls.clear();
        assertThat(policy.isRevocationChecked()).isTrue();
        assertThat(policy.crls()).hasSize(1);
        assertThatThrownBy(() -> policy.crls().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(TlsPeerPolicy.withoutRevocationChecks().isRevocationChecked()).isFalse();
        assertThatThrownBy(TlsPeerPolicy::withCrls).isInstanceOf(IllegalArgumentException.class);
        var unboundedBuilder = new org.bouncycastle.cert.X509v2CRLBuilder(
                org.bouncycastle.asn1.x500.X500Name.getInstance(ROOT.getSubjectX500Principal().getEncoded()),
                java.util.Date.from(NOW.minusSeconds(30)));
        X509CRL unbounded = new org.bouncycastle.cert.jcajce.JcaX509CRLConverter().getCRL(unboundedBuilder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(ROOT_KEYS.getPrivate())));
        assertThatThrownBy(() -> TlsPeerPolicy.withCrls(unbounded)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nextUpdate");
    }

    @Test
    void oneImmutableManagerValidatesConcurrentPeersWithoutMixedResults() throws Exception {
        var manager = manager(TrustBundle.of(ROOT), TlsPeerPolicy.withCrls(crl(ROOT, ROOT_KEYS, false)));
        var executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int index = 0; index < 16; index++) {
                boolean valid = index % 2 == 0;
                tasks.add(() -> {
                    try {
                        manager.checkClientTrusted(new X509Certificate[] {valid ? CLIENT : SERVER}, "EC");
                        return valid;
                    } catch (CertificateException e) {
                        return !valid;
                    }
                });
            }
            for (var result : executor.invokeAll(tasks)) assertThat(result.get()).isTrue();
        } finally {
            executor.shutdownNow();
        }
    }

    private static X509ExtendedTrustManager manager(TrustBundle trust, TlsPeerPolicy policy) {
        return TlsTrustManagers.create(trust, policy);
    }

    private static void assertRejected(X509ExtendedTrustManager manager, X509Certificate certificate) {
        assertThatThrownBy(() -> manager.checkClientTrusted(new X509Certificate[] {certificate}, "EC"))
                .isInstanceOf(CertificateException.class);
    }

    private static X509CRL crl(X509Certificate issuer, KeyPair keys, boolean revokeClient) {
        var builder = PkiCrl.issued().issuer(issuer, keys.getPrivate()).thisUpdate(NOW.minusSeconds(30))
                .nextUpdate(Duration.ofHours(1));
        if (revokeClient) builder.revoke(CLIENT, RevocationReason.KEY_COMPROMISE);
        return builder.build();
    }

    private static X509Certificate rawClient(Instant start, Duration validity, boolean ca, KeyUsage[] usage,
                                             ExtendedKeyUsage[] purposes) {
        return PkiCertificate.signed().subject("CN=Raw peer").keyPair(LEAF_KEYS).issuer(ROOT, ROOT_KEYS.getPrivate())
                .validFrom(start).validFor(validity).isCA(ca).keyUsage(usage).extendedKeyUsage(purposes).build();
    }
}
