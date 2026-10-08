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
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HexFormat;
import java.util.function.Consumer;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

class SelfSignedExtensionsTest {

    @Test
    void selfSignedSanAndEkuMatchIssuedCertificatesIncludingAccumulation() throws Exception {
        KeyPair keys = PkiKeys.ed25519();
        X509Certificate root = builder(keys).isCA(true).build();
        Consumer<SanBuilder> firstNames = san -> san.dns("service.example")
                .ip("192.0.2.10").ip("2001:db8::1");
        Consumer<SanBuilder> moreNames = san -> san.dns("service.example")
                .email("admin@example.com").uri("https://service.example");
        X509Certificate self = builder(keys).keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .san(firstNames).san(moreNames)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT, ExtendedKeyUsage.TLS_SERVER)
                .build();
        X509Certificate issued = PkiCertificate.signed().subject("CN=service.example")
                .keyPair(keys).issuer(root, keys.getPrivate()).validFor(Duration.ofDays(1))
                .san(firstNames).san(moreNames)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER)
                .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT, ExtendedKeyUsage.TLS_SERVER)
                .build();

        var holder = new X509CertificateHolder(self.getEncoded());
        for (var oid : new org.bouncycastle.asn1.ASN1ObjectIdentifier[] {
                Extension.subjectAlternativeName, Extension.extendedKeyUsage}) {
            assertThat(holder.getExtension(oid).isCritical()).isFalse();
            assertThat(self.getExtensionValue(oid.getId())).isEqualTo(issued.getExtensionValue(oid.getId()));
            assertThat(self.getNonCriticalExtensionOIDs()).contains(oid.getId());
        }
        assertThat(self.getCriticalExtensionOIDs()).contains(
                Extension.basicConstraints.getId(), Extension.keyUsage.getId());
        GeneralName[] names = GeneralNames.fromExtensions(holder.getExtensions(),
                Extension.subjectAlternativeName).getNames();
        assertThat(names).extracting(GeneralName::getTagNo).containsExactly(
                GeneralName.dNSName, GeneralName.iPAddress, GeneralName.iPAddress,
                GeneralName.dNSName, GeneralName.rfc822Name, GeneralName.uniformResourceIdentifier);
        assertThat(names[0]).isEqualTo(names[3]);
        assertThat(ASN1OctetString.getInstance(names[1].getName()).getOctets())
                .isEqualTo(new byte[] {(byte) 192, 0, 2, 10});
        assertThat(ASN1OctetString.getInstance(names[2].getName()).getOctets())
                .isEqualTo(HexFormat.of().parseHex("20010db8000000000000000000000001"));
        var eku = org.bouncycastle.asn1.x509.ExtendedKeyUsage.fromExtensions(holder.getExtensions());
        assertThat(eku.getUsages()).containsExactly(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);
        assertThat(self.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2");
        PkiCertInfo info = PkiCertInfo.of(self);
        assertThat(info.getSans()).hasSize(6).contains(
                new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "service.example"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.IP_ADDRESS, "192.0.2.10"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.EMAIL, "admin@example.com"),
                new SubjectAlternativeName(SubjectAlternativeName.Type.URI, "https://service.example"));
        assertThat(info.getSans()).filteredOn(san -> san.type() == SubjectAlternativeName.Type.IP_ADDRESS)
                .hasSize(2);
        assertThat(info.getExtendedKeyUsages()).containsExactly(ExtendedKeyUsage.TLS_SERVER, ExtendedKeyUsage.TLS_CLIENT);
        self.verify(self.getPublicKey());
    }

    @Test
    void repeatedBuildsAndFreshBuildersDoNotLeakExtensions() throws Exception {
        KeyPair keys = PkiKeys.ed25519();
        SelfSignedCertificateBuilder reused = builder(keys).san(s -> s.dns("first.example"))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER);
        X509Certificate first = reused.build();
        X509Certificate second = reused.san(s -> s.ip("127.0.0.1"))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_CLIENT).build();
        assertThat(first.getSubjectAlternativeNames()).hasSize(1);
        assertThat(first.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
        assertThat(second.getSubjectAlternativeNames()).hasSize(2);
        assertThat(second.getExtendedKeyUsage()).hasSize(2);
        for (X509Certificate fresh : new X509Certificate[] {
                builder(keys).build(), builder(keys).san(s -> {}).extendedKeyUsage().build()}) {
            assertThat(fresh.getExtensionValue(Extension.subjectAlternativeName.getId())).isNull();
            assertThat(fresh.getExtensionValue(Extension.extendedKeyUsage.getId())).isNull();
            assertThat(PkiCertInfo.of(fresh).getSans()).isEmpty();
            assertThat(PkiCertInfo.of(fresh).getExtendedKeyUsages()).isEmpty();
        }
    }

    @Test
    void externalSignerAlsoSupportsSanAndEku() throws Exception {
        KeyPair keys = PkiKeys.ed25519();
        X509Certificate certificate = PkiCertificate.selfSigned().subject("CN=External")
                .signer(keys.getPublic(), PkiSigner.jca(keys.getPrivate()))
                .validFor(Duration.ofDays(1)).san(s -> s.dns("external.example"))
                .extendedKeyUsage(ExtendedKeyUsage.TLS_SERVER).build();
        assertThat(PkiCertInfo.of(certificate).getSans()).containsExactly(
                new SubjectAlternativeName(SubjectAlternativeName.Type.DNS, "external.example"));
        assertThat(PkiCertInfo.of(certificate).getExtendedKeyUsages()).containsExactly(ExtendedKeyUsage.TLS_SERVER);
        certificate.verify(certificate.getPublicKey());
    }

    @Test
    void newConfigurerMethodsRejectNulls() {
        SelfSignedCertificateBuilder builder = PkiCertificate.selfSigned();
        assertThatNullPointerException().isThrownBy(() -> builder.san(null));
        assertThatNullPointerException().isThrownBy(() -> builder.extendedKeyUsage((ExtendedKeyUsage[]) null));
        assertThatNullPointerException().isThrownBy(() -> builder.extendedKeyUsage((ExtendedKeyUsage) null));
        assertThatNullPointerException().isThrownBy(() -> builder.san(s -> s.dns(null)));
        assertThatNullPointerException().isThrownBy(() -> builder.san(s -> s.ip(null)));
    }

    private static SelfSignedCertificateBuilder builder(KeyPair keys) {
        return PkiCertificate.selfSigned().subject("CN=service.example")
                .keyPair(keys).validFor(Duration.ofDays(1));
    }
}
