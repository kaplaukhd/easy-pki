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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Immutable, inspectable PKCS#10 certificate signing request.
 *
 * <p>Reading validates structure but deliberately does not validate the signature.
 * {@link #verifySignature()} proves possession of the requested public key only;
 * it establishes neither trust in the requester nor authorization for the subject
 * or any requested extension. An issuer must apply its own explicit policy.
 * Parse errors use {@link IllegalArgumentException}; file or stream failures use
 * {@link UncheckedIOException}. No provider is registered globally.
 */
public final class CsrRequest {
    private final byte[] der;
    private final byte[] requestInfo;
    private final X500Principal subject;
    private final PublicKey publicKey;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final byte[] signature;
    private final List<CsrExtension> requestedExtensions;
    private final List<CsrAttribute> attributes;

    private CsrRequest(byte[] der, byte[] requestInfo, X500Principal subject,
                       PublicKey publicKey, AlgorithmIdentifier signatureAlgorithm, byte[] signature,
                       List<CsrExtension> requestedExtensions, List<CsrAttribute> attributes) {
        this.der = der;
        this.requestInfo = requestInfo;
        this.subject = subject;
        this.publicKey = publicKey;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
        this.requestedExtensions = List.copyOf(requestedExtensions);
        this.attributes = List.copyOf(attributes);
    }

    /**
     * Parses exactly one DER-encoded PKCS#10 request. Rejects non-DER encodings,
     * trailing content, unsupported request versions and ambiguous extension requests.
     * The signature may be invalid; use {@link #requireValidSignature()} to require proof of possession.
     */
    public static CsrRequest fromDer(byte[] der) {
        byte[] copy = Objects.requireNonNull(der, "der").clone();
        try {
            ASN1Sequence request = sequence(requireDer(copy), 3, "PKCS#10 request");
            ASN1Sequence info = sequence(request.getObjectAt(0), 4, "CertificationRequestInfo");
            if (!ASN1Integer.getInstance(info.getObjectAt(0)).hasValue(0)) {
                throw new IllegalArgumentException("PKCS#10 version must be 0");
            }
            X500Principal subject = new X500Principal(info.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            ASN1Sequence keySequence = sequence(info.getObjectAt(2), 2, "SubjectPublicKeyInfo");
            algorithmIdentifier(keySequence.getObjectAt(0));
            ASN1BitString keyBits = ASN1BitString.getInstance(keySequence.getObjectAt(1));
            if (keyBits.getPadBits() != 0 || keyBits.getBytes().length == 0) {
                throw new IllegalArgumentException("CSR public key must be a nonempty octet-aligned BIT STRING");
            }
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keySequence);
            PublicKey publicKey = publicKey(keyInfo);
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(info.getObjectAt(3));
            if (!tagged.hasContextTag(0)) throw new IllegalArgumentException("CSR attributes require context tag 0");
            ASN1Set attributeSet = ASN1Set.getInstance(tagged, false);
            List<CsrAttribute> attributes = new ArrayList<>();
            List<CsrExtension> extensions = new ArrayList<>();
            readAttributes(attributeSet, attributes, extensions);
            // The context-specific tag hides a SET from generic DER canonicalization.
            // Reconstruct it as an implicit SET to also enforce its canonical ordering.
            ASN1Sequence normalizedInfo = new DERSequence(new ASN1Encodable[] {
                    info.getObjectAt(0), info.getObjectAt(1), keyInfo,
                    new DERTaggedObject(false, 0, attributeSet)});
            if (!Arrays.equals(info.getEncoded(ASN1Encoding.DER), normalizedInfo.getEncoded(ASN1Encoding.DER))) {
                throw new IllegalArgumentException("CSR attributes must use canonical implicit SET encoding");
            }
            AlgorithmIdentifier algorithm = algorithmIdentifier(request.getObjectAt(1));
            ASN1BitString signature = ASN1BitString.getInstance(request.getObjectAt(2));
            if (signature.getPadBits() != 0 || signature.getBytes().length == 0) {
                throw new IllegalArgumentException("CSR signature must be a nonempty octet-aligned BIT STRING");
            }
            return new CsrRequest(copy, info.getEncoded(ASN1Encoding.DER), subject, publicKey,
                    algorithm, signature.getOctets(), extensions, attributes);
        } catch (IOException | GeneralSecurityException | ClassCastException e) {
            throw new IllegalArgumentException("Invalid PKCS#10 request", e);
        }
    }

    /**
     * Parses exactly one PEM request with a CERTIFICATE REQUEST or NEW CERTIFICATE
     * REQUEST label. Only whitespace may surround the block; other objects and trailing text are rejected.
     */
    public static CsrRequest fromPem(String pem) {
        String text = Objects.requireNonNull(pem, "pem").strip();
        String label = text.startsWith("-----BEGIN NEW CERTIFICATE REQUEST-----")
                ? "NEW CERTIFICATE REQUEST" : "CERTIFICATE REQUEST";
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        if (!text.startsWith(begin) || !text.endsWith(end)) {
            throw new IllegalArgumentException("Expected exactly one PEM certificate request");
        }
        String payload = text.substring(begin.length(), text.length() - end.length())
                .replaceAll("[ \t\r\n]", "");
        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            if (!Base64.getEncoder().encodeToString(decoded).equals(payload)) {
                throw new IllegalArgumentException("Noncanonical PEM Base64 encoding");
            }
            return fromDer(decoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid PEM certificate request", e);
        }
    }

    /** Parses one PEM request from a reader, closing the reader after use. */
    public static CsrRequest fromPem(Reader reader) {
        Objects.requireNonNull(reader, "reader");
        try (reader) {
            StringWriter text = new StringWriter();
            reader.transferTo(text);
            return fromPem(text.toString());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read PEM certificate request", e);
        }
    }

    /** Parses one UTF-8 PEM request from a stream, closing the stream after use. */
    public static CsrRequest fromPem(InputStream input) {
        Objects.requireNonNull(input, "input");
        return fromPem(new InputStreamReader(input, StandardCharsets.UTF_8));
    }

    /** Reads exactly one PEM or DER request from a file, detecting the format. */
    public static CsrRequest fromFile(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            byte[] bytes = Files.readAllBytes(path);
            int start = 0;
            while (start < bytes.length && (bytes[start] == ' ' || bytes[start] == '\t'
                    || bytes[start] == '\r' || bytes[start] == '\n')) start++;
            return start < bytes.length && bytes[start] == '-'
                    ? fromPem(new String(bytes, StandardCharsets.UTF_8)) : fromDer(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read certificate request " + path, e);
        }
    }

    /** Returns the requested subject, without making an identity or authorization claim. */
    public X500Principal getSubject() { return subject; }

    /** Returns the public key carried by the request. */
    public PublicKey getPublicKey() { return publicKey; }

    /** Returns an unmodifiable list of requested extensions, including unknown OIDs. */
    public List<CsrExtension> getRequestedExtensions() { return requestedExtensions; }

    /** Returns unrecognized request attributes, excluding the decoded extensionRequest attribute. */
    public List<CsrAttribute> getAttributes() { return attributes; }

    /** Returns a defensive copy of the original DER encoding. */
    public byte[] toDer() { return der.clone(); }

    /** Returns a PEM encoding with the standard CERTIFICATE REQUEST label. */
    public String toPem() {
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    /**
     * Checks proof of possession using the request's public key and encoded algorithm
     * parameters. Returns false for an invalid signature or unsupported algorithm or parameters.
     * A true result does not establish identity, trust or issuance authorization.
     */
    public boolean verifySignature() {
        return CsrSignatureSupport.verify(publicKey, signatureAlgorithm, requestInfo, signature);
    }

    /** Requires valid proof of possession; throws IllegalArgumentException otherwise. */
    public void requireValidSignature() {
        if (!verifySignature()) throw new IllegalArgumentException("CSR signature is invalid or unsupported");
    }

    static ASN1Primitive requireDer(byte[] bytes) {
        try {
            ASN1Primitive value = ASN1Primitive.fromByteArray(bytes);
            if (value == null || !Arrays.equals(bytes, value.getEncoded(ASN1Encoding.DER))) {
                throw new IllegalArgumentException("Expected exactly one canonical DER value");
            }
            return value;
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid DER encoding", e);
        }
    }

    private static ASN1Sequence sequence(ASN1Encodable value, int size, String description) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(value);
        if (sequence.size() != size) throw new IllegalArgumentException("Invalid " + description + " field count");
        return sequence;
    }

    static AlgorithmIdentifier algorithmIdentifier(ASN1Encodable value) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(value);
        if (sequence.size() < 1 || sequence.size() > 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier field count");
        }
        return AlgorithmIdentifier.getInstance(sequence);
    }

    private static PublicKey publicKey(SubjectPublicKeyInfo keyInfo) throws GeneralSecurityException, IOException {
        String oid = keyInfo.getAlgorithm().getAlgorithm().getId();
        String algorithm = switch (oid) {
            case "1.2.840.113549.1.1.1" -> "RSA";
            case "1.2.840.113549.1.1.10" -> "RSASSA-PSS";
            case "1.2.840.10045.2.1" -> "EC";
            case "1.3.101.112" -> "Ed25519";
            default -> oid;
        };
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(keyInfo.getEncoded(ASN1Encoding.DER)));
    }

    private static void readAttributes(ASN1Set attributeSet, List<CsrAttribute> attributes,
                                       List<CsrExtension> extensions) throws IOException {
        boolean extensionRequestFound = false;
        for (ASN1Encodable entry : attributeSet) {
            ASN1Sequence attribute = sequence(entry, 2, "CSR attribute");
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(attribute.getObjectAt(0));
            ASN1Set values = ASN1Set.getInstance(attribute.getObjectAt(1));
            if (values.size() == 0) throw new IllegalArgumentException("CSR attribute must contain a value");
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(oid)) {
                if (extensionRequestFound || values.size() != 1) {
                    throw new IllegalArgumentException("CSR must have at most one extensionRequest attribute with one value");
                }
                extensionRequestFound = true;
                readExtensions(ASN1Sequence.getInstance(values.getObjectAt(0)), extensions);
            } else {
                List<byte[]> encodedValues = new ArrayList<>();
                for (ASN1Encodable value : values) encodedValues.add(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
                attributes.add(new CsrAttribute(oid.getId(), encodedValues));
            }
        }
    }

    private static void readExtensions(ASN1Sequence sequence, List<CsrExtension> extensions) {
        if (sequence.size() == 0) throw new IllegalArgumentException("extensionRequest must contain at least one extension");
        Set<String> seen = new HashSet<>();
        for (ASN1Encodable entry : sequence) {
            ASN1Sequence extension = ASN1Sequence.getInstance(entry);
            if (extension.size() != 2 && extension.size() != 3) throw new IllegalArgumentException("Invalid requested extension");
            String oid = ASN1ObjectIdentifier.getInstance(extension.getObjectAt(0)).getId();
            if (!seen.add(oid)) throw new IllegalArgumentException("Duplicate requested extension OID: " + oid);
            boolean critical = extension.size() == 3 && ASN1Boolean.getInstance(extension.getObjectAt(1)).isTrue();
            if (extension.size() == 3 && !critical) throw new IllegalArgumentException("DER omits the default critical=false flag");
            byte[] value = ASN1OctetString.getInstance(extension.getObjectAt(extension.size() - 1)).getOctets();
            extensions.add(new CsrExtension(oid, critical, value));
        }
    }
}
