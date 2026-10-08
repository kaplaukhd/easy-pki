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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.Test;

class CsrSanEncodingTest {
    private static final KeyPair KEYS = PkiKeys.ec(Curve.P_256);
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");
    private static final byte[] MAPPED_V6 = HexFormat.of().parseHex("00000000000000000000ffffc0000201");

    @Test
    void authorizationAndIssuancePreserveIpv4MappedIpv6AddressFamilyAndOctets() throws Exception {
        CsrRequest request = withSan(new GeneralNames(new GeneralName(GeneralName.iPAddress,
                new DEROctetString(MAPPED_V6))).getEncoded());
        AtomicReference<String> approvedAddress = new AtomicReference<>();
        CsrIssuancePolicy policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> true).allowSan(name -> {
                    approvedAddress.set(name.value());
                    return name.type() == SubjectAlternativeName.Type.IP_ADDRESS
                            && name.value().contains(":");
                }).build();
        X509Certificate certificate = issue(request, policy, issuer(new AtomicInteger()));
        assertThat(approvedAddress.get()).contains(":");
        byte[] authorizedOctets = ASN1OctetString.getInstance(
                new GeneralName(GeneralName.iPAddress, approvedAddress.get()).getName()).getOctets();
        assertThat(authorizedOctets).isEqualTo(MAPPED_V6);
        byte[] encodedNames = ASN1OctetString.getInstance(certificate.getExtensionValue(
                Extension.subjectAlternativeName.getId())).getOctets();
        GeneralName[] names = GeneralNames.getInstance(encodedNames).getNames();
        assertThat(names).hasSize(1);
        byte[] issuedOctets = ASN1OctetString.getInstance(names[0].getName()).getOctets();
        assertThat(issuedOctets).hasSize(16).isEqualTo(MAPPED_V6);
    }

    @Test
    void anIpv4OnlyAuthorizationDoesNotAuthorizeAMappedIpv6Request() throws Exception {
        CsrRequest request = withSan(new GeneralNames(new GeneralName(GeneralName.iPAddress,
                new DEROctetString(MAPPED_V6))).getEncoded());
        CsrIssuancePolicy policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> true).allowSan(name -> name.value().equals("192.0.2.1")).build();
        AtomicInteger calls = new AtomicInteger();
        PkiIdentity identity = issuer(calls);
        calls.set(0);
        assertThatThrownBy(() -> issue(request, policy, identity)).isInstanceOf(IllegalArgumentException.class);
        assertThat(calls).hasValue(0);
    }

    @Test
    void rejectsExplicitIpSanTagBeforeAuthorizationOrSigning() throws Exception {
        // iPAddress uses primitive IMPLICIT [7]; an explicit OCTET STRING wrapper is malformed.
        byte[] malformed = new DERSequence(new DERTaggedObject(true, GeneralName.iPAddress,
                new DEROctetString(new byte[] {(byte) 192, 0, 2, 1}))).getEncoded();
        CsrRequest request = withSan(malformed);
        assertThat(request.verifySignature()).isTrue();
        AtomicInteger callbacks = new AtomicInteger();
        CsrIssuancePolicy policy = CsrIssuancePolicy.forProfile(CertificateProfile.TLS_SERVER)
                .allowSubject(subject -> { callbacks.incrementAndGet(); return true; })
                .allowSan(name -> { callbacks.incrementAndGet(); return true; }).build();
        AtomicInteger calls = new AtomicInteger();
        PkiIdentity identity = issuer(calls);
        calls.set(0);
        assertThatThrownBy(() -> issue(request, policy, identity)).isInstanceOf(IllegalArgumentException.class);
        assertThat(callbacks).hasValue(0);
        assertThat(calls).hasValue(0);
    }

    private static CsrRequest withSan(byte[] encoded) {
        return PkiCsr.create().subject("CN=Requested address").keyPair(KEYS)
                .extension(new CsrExtension(Extension.subjectAlternativeName.getId(), false, encoded)).build();
    }

    private static X509Certificate issue(CsrRequest request, CsrIssuancePolicy policy, PkiIdentity issuer) {
        return PkiCsr.issue(request, policy).issuer(issuer).validFrom(START).validFor(Duration.ofDays(1)).build();
    }

    private static PkiIdentity issuer(AtomicInteger calls) {
        X509Certificate root = PkiCertificate.rootCa().subject("CN=SAN regression root").keyPair(KEYS)
                .validFrom(START.minusSeconds(1)).validFor(Duration.ofDays(365)).build();
        PkiSigner delegate = PkiSigner.jca(KEYS.getPrivate());
        PkiSigner counted = new PkiSigner() {
            @Override public String signatureAlgorithm() { return delegate.signatureAlgorithm(); }
            @Override public byte[] sign(byte[] content) throws GeneralSecurityException {
                calls.incrementAndGet();
                return delegate.sign(content);
            }
        };
        return PkiIdentity.of(root, counted);
    }
}
