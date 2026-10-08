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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TlsProfileNamesTest {

    @Test
    void serverRequiresNamesAndClientMayRelyOnTheSubject() {
        GeneralNames empty = new GeneralNames(new GeneralName[0]);
        assertThat(TlsProfileNames.hasNames(null)).isFalse();
        assertThat(TlsProfileNames.hasNames(empty)).isFalse();
        assertThat(TlsProfileNames.hasNames(name(GeneralName.dNSName, "localhost"))).isTrue();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(null))
                .withMessageContaining("requires at least one");
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(empty));
        assertThatCode(() -> TlsProfileNames.validateClient(null)).doesNotThrowAnyException();
        assertThatCode(() -> TlsProfileNames.validateClient(empty)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "service", "api.example.com", "API.Example.COM", "1node.example",
            "api-v2.example", "xn--bcher-kva.example", "*.example.com", "*.internal.example.com"})
    void acceptsOrdinaryAsciiAndBoundedWildcardDnsNames(String value) {
        validateBoth(name(GeneralName.dNSName, value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", ".", ".example", "example.", "a..example", "-api.example",
            "api-.example", "api_example", "api example", "api\nexample", "api\u0000example",
            "*", "*.com", "*api.example.com", "api*.example.com", "api.*.example.com",
            "*.*.example.com", "https://api.example.com", "b\u00fccher.example", "192.0.2.10",
            "127.0.0.1", "2001:db8::1", "::1", "*.192.0.2.10"})
    void rejectsMalformedDnsNamesAndIpLiterals(String value) {
        rejectBoth(name(GeneralName.dNSName, value));
    }

    @Test
    void enforcesDnsLabelAndOverallLengthBoundaries() {
        String longLabel = "a".repeat(63);
        validateBoth(name(GeneralName.dNSName, longLabel + ".example"));
        validateBoth(name(GeneralName.dNSName,
                longLabel + "." + longLabel + "." + longLabel + "." + "a".repeat(61)));
        rejectBoth(name(GeneralName.dNSName, "a".repeat(64) + ".example"));
        rejectBoth(name(GeneralName.dNSName,
                longLabel + "." + longLabel + "." + longLabel + "." + "a".repeat(62)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.0.2.10", "127.0.0.1", "0.0.0.0", "2001:db8::1", "::1", "::",
            "::ffff:192.0.2.10"})
    void acceptsEncodedIpv4AndIpv6(String value) {
        validateBoth(name(GeneralName.iPAddress, value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.0.2.10/24", "192.0.2.10/255.255.255.0", "2001:db8::1/64",
            "2001:db8::1/ffff:ffff:ffff:ffff::"})
    void rejectsIpAddressAndMaskEncodingsAcceptedByBouncyCastle(String value) {
        rejectBoth(name(GeneralName.iPAddress, value));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 3, 5, 8, 15, 17, 32})
    void rejectsMalformedEncodedIpLengths(int length) {
        rejectBoth(new GeneralNames(new GeneralName(GeneralName.iPAddress, new DEROctetString(new byte[length]))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"alice@example.com", "alice.smith+service@example.com", "admin@localhost",
            "o'hara@example.com", "a!#$%&'*+-/=?^_`{|}~z@example.com"})
    void acceptsConservativeAsciiClientMailboxes(String value) {
        GeneralNames names = name(GeneralName.rfc822Name, value);
        assertThatCode(() -> TlsProfileNames.validateClient(names)).doesNotThrowAnyException();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(names))
                .withMessageContaining("Unsupported SAN type");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "alice", "@example.com", "alice@", "alice@@example.com",
            "alice smith@example.com", "Alice <alice@example.com>", "alice(comment)@example.com",
            "\"alice smith\"@example.com", "alice@[192.0.2.10]", "alice@192.0.2.10",
            "alice@*.example.com", "alice@-example.com", "alice@example.com.", ".alice@example.com",
            "alice.@example.com", "alice..smith@example.com", "al\u00efce@example.com"})
    void rejectsUnsupportedOrMalformedClientMailboxForms(String value) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> TlsProfileNames.validateClient(name(GeneralName.rfc822Name, value)));
    }

    @Test
    void enforcesMailboxLengthBoundaries() {
        String local = "a".repeat(64);
        assertThatCode(() -> TlsProfileNames.validateClient(name(GeneralName.rfc822Name, local + "@example.com")))
                .doesNotThrowAnyException();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateClient(
                name(GeneralName.rfc822Name, local + "a@example.com")));
        String domain = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(61);
        assertThatCode(() -> TlsProfileNames.validateClient(name(GeneralName.rfc822Name, local + "@" + domain)))
                .doesNotThrowAnyException();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateClient(
                name(GeneralName.rfc822Name, local + "@" + domain + "d")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"spiffe://example.org/workload/api", "urn:example:client:123", "mailto:alice@example.com",
            "https://example.com/client?id=123", "https://[2001:db8::1]/client", "urn:example:caf%C3%A9"})
    void acceptsAbsoluteAsciiClientUris(String value) {
        GeneralNames names = name(GeneralName.uniformResourceIdentifier, value);
        assertThatCode(() -> TlsProfileNames.validateClient(names)).doesNotThrowAnyException();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(names))
                .withMessageContaining("Unsupported SAN type");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "client/123", "//example.com/client", "example.com", ":client", "urn:",
            "urn:#fragment", "https://", "https://example.com/client name", "https://example.com/%zz",
            "https://example.com/caf\u00e9", "urn:client\nname"})
    void rejectsRelativeEmptyNonAsciiAndMalformedClientUris(String value) {
        assertThatIllegalArgumentException().isThrownBy(
                () -> TlsProfileNames.validateClient(name(GeneralName.uniformResourceIdentifier, value)));
    }

    @ParameterizedTest
    @ValueSource(ints = {GeneralName.otherName, GeneralName.x400Address, GeneralName.directoryName,
            GeneralName.ediPartyName, GeneralName.registeredID, 99})
    void rejectsUnsupportedGeneralNameTags(int tag) {
        rejectBoth(new GeneralNames(new GeneralName(tag, new DERUTF8String("identity"))));
    }

    @ParameterizedTest
    @ValueSource(ints = {GeneralName.dNSName, GeneralName.iPAddress, GeneralName.rfc822Name,
            GeneralName.uniformResourceIdentifier})
    void rejectsIncorrectAsn1ValueTypes(int tag) {
        rejectBoth(new GeneralNames(new GeneralName(tag, new DERUTF8String("api.example.com"))));
    }

    @Test
    void validatesEveryEntryInMixedSanCollections() {
        GeneralNames valid = new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "api.example.com"),
                new GeneralName(GeneralName.iPAddress, "192.0.2.10")});
        validateBoth(valid);
        rejectBoth(new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "api.example.com"),
                new GeneralName(GeneralName.dNSName, "bad_name.example")}));
        GeneralNames clientOnly = new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "client.example.com"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "urn:example:client:123"),
                new GeneralName(GeneralName.rfc822Name, "alice@example.com")});
        assertThatCode(() -> TlsProfileNames.validateClient(clientOnly)).doesNotThrowAnyException();
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(clientOnly));
    }

    private static GeneralNames name(int tag, String value) {
        return new GeneralNames(new GeneralName(tag, value));
    }

    private static void validateBoth(GeneralNames names) {
        assertThatCode(() -> TlsProfileNames.validateServer(names)).doesNotThrowAnyException();
        assertThatCode(() -> TlsProfileNames.validateClient(names)).doesNotThrowAnyException();
    }

    private static void rejectBoth(GeneralNames names) {
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateServer(names));
        assertThatIllegalArgumentException().isThrownBy(() -> TlsProfileNames.validateClient(names));
    }
}
