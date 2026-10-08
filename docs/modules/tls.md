# TLS and rotation

`easy-pki-tls` adapts `PkiIdentity` and `TrustBundle` to JSSE key managers,
trust managers and an `SSLContext`. It adds peer checks and publishes complete
identity/trust generations atomically. It depends on core and validation; no
Spring dependency or global provider registration is required.

## Create a context

```java
import io.github.kaplaukhd.easypki.*;
import io.github.kaplaukhd.easypki.tls.*;

ReloadableTlsContext tls = PkiTls.builder()
    .identity(localIdentity)
    .trust(peerTrust)
    .peerPolicy(TlsPeerPolicy.withoutRevocationChecks())
    .build();

SSLContext context = tls.getSslContext();
KeyManager[] keys = tls.getSnapshot().getKeyManagers();
TrustManager[] trust = tls.getSnapshot().getTrustManagers();
```

The JSSE types are in `javax.net.ssl`. `localIdentity` is a checked
`PkiIdentity` with a JCA private-key handle, and `peerTrust` is an explicit
`TrustBundle`. A client which presents no certificate can omit `identity(...)`.
Trust and peer policy are mandatory. An empty trust bundle rejects all peers;
it never falls back to platform trust. Local identity chains never supply peer
trust implicitly: the local and peer authorities may be completely different.

Preparation checks current identity-chain validity, end-entity role, explicit
TLS EKU, digitalSignature usage, known issuer signing authority and path
constraints. The supplied chain is checked against its terminal certificate
for consistency; that terminal certificate does not become a peer anchor.
Missing issuers are not discovered. Unsupported terminal name/policy constraints
fail preparation. Private key possession and chain links are already verified
by `PkiIdentity` construction. The application must keep the key backend stable.

Identity stores hold the `PrivateKey` handle and cannot be serialized or
modified. Known Bouncy Castle Ed25519 software keys use a nonserializable JCA
interface view that normalizes the algorithm label to the `EdDSA` expected by
SunJSSE; the signing provider accesses the existing key through `EdECPrivateKey`.
Other handles, including opaque provider keys, retain their exact identity. The
adapter does not call private-key `getEncoded()`, read the seed while creating
the view, or close/destroy the key backend. An opaque key requires installed JCA/JSSE
providers that support the signatures negotiated by TLS, including RSA-PSS
where selected. A signer-only `PkiIdentity` has no portable JSSE key adapter and
is rejected. This is not a promise of support for every HSM or custom provider.

## Mutual TLS sockets and engines

```java
SSLServerSocket listener = (SSLServerSocket)
    serverTls.getSslContext().getServerSocketFactory().createServerSocket(8443);
listener.setNeedClientAuth(true);
try (SSLSocket accepted = (SSLSocket) listener.accept()) {
    accepted.setSoTimeout(5000);
    accepted.startHandshake();
    // Authenticate first, then read or write application data.
}
```

Server sockets and engines default to requiring a client certificate. A caller
can explicitly change the JSSE client-auth configuration for one-way TLS. TLS
1.3 and TLS 1.2 are enabled by default. Applications own socket timeouts, closing,
client authorization and connection-pool lifecycle.

```java
try (SSLSocket connection = (SSLSocket)
        clientTls.getSslContext().getSocketFactory().createSocket("api.example.com", 8443)) {
    connection.setSoTimeout(5000);
    connection.startHandshake();
    // The server certificate must match the supplied reference name.
}

SSLEngine clientEngine = clientTls.getSslContext().createSSLEngine("api.example.com", 8443);
clientEngine.setUseClientMode(true);
SSLEngine serverEngine = serverTls.getSslContext().createSSLEngine();
serverEngine.setUseClientMode(false);
serverEngine.setNeedClientAuth(true);
```

Engines need an application-managed I/O loop. When layering TLS over an existing
socket, supply the intended reference hostname to
`createSocket(socket, hostname, port, autoClose)`. The `InetAddress` overloads
use the numeric IP literal, not reverse DNS. Server trust-manager calls without
a socket or engine/reference host are rejected because identity cannot be
checked from a certificate chain alone.

## Peer policy and revocation

Every peer must pass the host provider's PKIX validation and negotiated
algorithm constraints, with a currently valid end-entity leaf, digitalSignature
KeyUsage and explicit serverAuth or clientAuth EKU. Even an explicitly trusted
leaf must satisfy the role checks. Client certificate authentication does not
assign application permissions.

Server identity uses DNS/IP SANs only, with no Common Name fallback. DNS matching
is case-insensitive. A wildcard is a complete leftmost label and matches exactly
one label. Supply internationalized reference names as ASCII A-labels. IPs match
exactly, retaining the distinction between IPv4 and IPv4-mapped IPv6. Matching
performs no DNS lookup and does not infer the expected name from SNI. URI/SRV
identities and automatic IDNA conversion are outside this bounded DNS/IP API.
These checks complement the host JSSE provider's own connection checks.

Choose revocation explicitly:

```java
TlsPeerPolicy offlinePolicy = TlsPeerPolicy.withCrls(rootCrl, intermediateCrl);
ReloadableTlsContext client = PkiTls.builder()
    .trust(peerTrust)
    .peerPolicy(offlinePolicy)
    .build();

client.reloadPeerPolicy(TlsPeerPolicy.withCrls(freshRootCrl, freshIntermediateCrl));
```

CRLs are immutable DER snapshots and require `nextUpdate` after `thisUpdate`.
Every certificate below the selected anchor needs valid, applicable evidence.
Missing, stale, revoked or unsupported evidence fails the handshake. The same
selected chain/anchor receives revocation and connection-specific checks.
This mode uses the existing bounded chain builder, with at most 19 intermediate
certificates. Only the complete direct CRL forms supported by the validation
module are accepted. It performs no OCSP, CDP fetch or stapled-response checking.
`withoutRevocationChecks()` explicitly opts out of revocation; other peer checks
remain active. Replacing the policy also creates a fresh TLS generation.

## Atomic updates

```java
TlsSnapshot before = tls.getSnapshot();

tls.reloadIdentity(replacementIdentity);
tls.reloadTrust(replacementPeerTrust);

// When the source provides one coordinated set, publish it in one operation.
TlsSnapshot published = tls.reload(replacementIdentity, replacementPeerTrust);
long generation = published.getGeneration();
```

Each update validates and initializes a candidate before publishing one atomic
reference. Invalid identity material or failed trust/policy initialization leaves
the previous generation active. Identity-only and trust-only updates serialize
with each other and retain the latest other half; they do not overwrite a
concurrent change. Use the paired update to avoid an intermediate combination
when both belong to one source version.

An empty trust update deliberately removes every anchor. Other trust updates
replace the set; they do not merge it. During CA rollover, explicitly publish
the union of old and new anchors for the overlap period, then publish only the
new anchors when appropriate. An explicitly selected anchor follows the existing
`TrustBundle` contract, including intermediate or leaf anchors; do not derive
anchors from an untrusted peer chain.

| Object | Generation boundary | Behavior after update |
|---|---|---|
| Stable `getSslContext()` result and its cached factories | Each socket/engine creation | New objects use the new generation |
| Already bound server socket from that context | Each completed TCP accept | New accepted sockets use the new generation |
| Already created socket/engine, even before handshake | Its creation/accept | Retains its original identity and trust |
| Established connection or reused HTTP connection | Original connection | Continues unchanged until closed |
| Managers or stores taken from `TlsSnapshot` | Snapshot acquisition | Fixed material; independently created contexts do not rotate |

A generation has its own fresh JSSE context and session/ticket state. A newly
created connection after a rotation cannot resume using the replaced context's
sessions. Existing connections remain usable, including when an anchor is
removed. Drain or close old connections when the application requires immediate
revocation of their access. Keep old key backends alive until their pinned
connections have finished. Do not try to disable sessions by setting timeout or
cache size to zero: JSSE defines those values as unlimited.

The managed context rejects `init(...)`; use the reload methods. Session-context
accessors refer to the current generation at the time they are called. Session
settings changed there are not a persistent policy for later generations.
The library does not implement file watchers, scheduled renewals or automatic
connection-pool eviction.

## Spring Boot

The starter can register an opt-in named SSL Bundle and adapt Tomcat and
`RestClient` to this same context. See the [Spring SSL Bundle guide](spring-boot.md)
for properties, custom context beans and supported consumer behavior. Adding the
starter alone does not enable a TLS server or require client certificates.

Contracts follow the [JSSE guide](https://docs.oracle.com/en/java/javase/17/security/java-secure-socket-extension-jsse-reference-guide.html),
[extended trust-manager API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/X509ExtendedTrustManager.html),
[session-context API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/SSLSessionContext.html)
and the DNS-ID/IP-ID subset of [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html).
