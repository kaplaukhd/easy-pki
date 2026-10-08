# easy-pki-spring-boot-starter

Spring Boot 3 auto-configuration for `easy-pki`. Add one dependency and a
few YAML keys — get a ready-to-inject `EasyPkiValidator`, a certificate-expiry
monitor, an Actuator health indicator and an mTLS filter for Spring Security.

## Configuration

```yaml
easy-pki:
  trust-store:
    path: classpath:truststore.p12
    password: changeit
    type: PKCS12           # default
  key-store:
    path: /etc/ssl/keystore.p12
    password: ${KEYSTORE_PASSWORD}
  validation:
    mode: OCSP_WITH_CRL_FALLBACK  # NONE | OCSP | CRL | OCSP_WITH_CRL_FALLBACK
    ocsp-timeout: 5s
    crl-cache-ttl: 30m
    http-timeout: 10s
    proxy: http://proxy.corp:3128
  monitoring:
    enabled: true
    warn-before: 30d
    check-interval: 12h

management:
  endpoints:
    web:
      exposure:
        include: health
```

Every key is optional — the starter auto-configures only what you turn on.

## Injectable beans

### `EasyPkiValidator`

Thread-safe facade around `CertValidator`, pre-wired with trust anchors from
the configured trust store and the revocation mode from
`easy-pki.validation.mode`.

Trust must be configured explicitly. Without a trust store or a custom
`EasyPkiValidator` bean supplying anchors, validation fails even if the peer
presents a complete chain with a self-signed root. `ValidationMode.NONE`
disables revocation checking only; it still requires trust and a valid PKIX
path. The chain passed to `validate(cert, chain...)` must be ordered from
the certificate's issuer upward and never supplies trust by itself.

```java
@Service
public class TlsService {
    private final EasyPkiValidator validator;

    public TlsService(EasyPkiValidator validator) {
        this.validator = validator;
    }

    public void check(X509Certificate clientCert, X509Certificate intermediate) {
        ValidationResult r = validator.validate(clientCert, intermediate);
        if (!r.isValid()) {
            throw new SecurityException(r.getErrors().toString());
        }
    }

    public CertValidator advanced(X509Certificate cert) {
        // for per-call tuning (e.g. at(Instant), extra static CRLs)
        return validator.newValidator(cert);
    }
}
```

`isTrusted()` reports linkage to an explicit anchor; use `isValid()` for the
overall decision, including PKIX and any configured revocation checks.

### `Pkcs12Bundle` qualified beans

When the corresponding property is set, the starter loads each bundle and
exposes it as a qualified bean:

| Qualifier | Source property |
|---|---|
| `easyPkiTrustStore` | `easy-pki.trust-store.path` |
| `easyPkiKeyStore`   | `easy-pki.key-store.path` |

```java
@Autowired
@Qualifier(EasyPkiAutoConfiguration.TRUST_STORE_BEAN)
Pkcs12Bundle trustStore;
```

The auto-loaded `easyPkiTrustStore` contains **every X.509 trusted certificate
entry**, read in alias order and deduplicated by certificate content through
the shared `TrustBundle` model. Private-key entries and the certificates in their
identity chains are ignored; add each intended anchor as a trusted certificate
entry. An empty store or a store containing only key entries fails startup with
a message that no trusted X.509 certificate entries were found.

For compatibility, this qualified trust-store bean remains a `Pkcs12Bundle`:
`getCertificate()` and `getAlias()` identify the first trusted entry,
`getPrivateKey()` returns `null`, and `getChain()` returns the complete, flat
list of anchors. In this trust-store snapshot, that list can contain unrelated
roots and is not an issuer chain. The validator, monitor and health indicator
all consume the complete list. The `easyPkiKeyStore` bean retains its existing
primary certificate, private key and ordered chain behavior.

Exporting this snapshot preserves every certificate. Its additional aliases
are generated from the primary alias because the Spring snapshot does not
retain the original aliases for those entries. To preserve aliases from a
trust-only file when re-exporting, load it directly with `PkiPkcs12.load(...)`;
see [PKCS#12 alias semantics](core.md#pkcs12).

The general [TrustBundle loaders](core.md#explicit-trust-bundles) also support
PEM and JKS for application-managed trust. The starter's automatic file loading
continues to use its existing PKCS#12 properties and named bundle bean.

## Named SSL bundles

The starter can register an `EasyPkiSslBundle` backed by the
`easy-pki-tls` module's `ReloadableTlsContext`. Registration is opt-in:
existing key-store, trust-store and validator settings alone do not enable TLS.
This example uses the configured stores for a Tomcat HTTPS server requiring
client certificates:

```yaml
easy-pki:
  key-store:
    path: file:/etc/ssl/server.p12
    password: ${SERVER_KEYSTORE_PASSWORD}
  trust-store:
    path: file:/etc/ssl/client-roots.p12
    password: ${CLIENT_TRUSTSTORE_PASSWORD}
  ssl:
    bundle-name: application
    revocation-mode: disabled # explicit TLS policy choice

server:
  port: 8443
  ssl:
    bundle: application
    client-auth: need
```

The key store must contain a valid TLS identity: an end-entity certificate,
its matching JCA private key and ordered presentation chain, with explicit
digitalSignature KU and the appropriate serverAuth/clientAuth EKU. The trust
store supplies only explicitly trusted certificate entries. The identity
chain never supplies peer trust, and missing trust does not fall back to the
JVM's root store. A client-only bundle may omit the key store; the Tomcat server
requires an identity. Existing qualified store bean overrides remain effective.

TLS peer policy is separate from `easy-pki.validation.mode`. For store-derived
TLS material, explicitly select `easy-pki.ssl.revocation-mode=disabled` or
supply one `TlsPeerPolicy` bean. Supplying both is rejected. Disabling revocation
retains PKIX, current validity, TLS usage and server SAN checks. To require
offline CRL evidence, omit the property and provide, for example:

```java
@Bean
TlsPeerPolicy tlsPeerPolicy(X509CRL currentCrl) {
    return TlsPeerPolicy.withCrls(currentCrl);
}
```

The supplied CRLs must cover the certificates below the selected trust anchor;
missing, stale, invalid or unsupported evidence fails the handshake. This
integration does not enable OCSP, network CRL retrieval or file watching.

### Use a bundle from a Spring REST client

Configure the client's named bundle with trust for the server, and a client
identity when the server requires mTLS. Spring Boot's `RestClientSsl` applies
the bundle to a supported request factory:

```java
@Bean
RestClient serviceClient(RestClient.Builder builder, RestClientSsl ssl) {
    return builder
        .baseUrl("https://service.example.com:8443")
        .apply(ssl.fromBundle("application"))
        .build();
}
```

`RestClientSsl` is in `org.springframework.boot.autoconfigure.web.client`;
`RestClient` is in `org.springframework.web.client`. Applying the SSL bundle
replaces an existing request factory. The tested Boot 3.3.5 default Java
connection factory uses the live TLS context. The peer must present a matching
DNS/IP SAN; Common Name fallback is disabled. TLS client-certificate acceptance
does not authorize access to application resources.

### Application-owned TLS material

Provide a `ReloadableTlsContext` bean to use application-managed identity,
trust and peer policy instead of creating TLS material from the configured
stores. With such a bean, `easy-pki.ssl.bundle-name` is sufficient; its peer
policy has already been explicitly chosen:

```java
@Bean
ReloadableTlsContext applicationTls(PkiIdentity localIdentity, TrustBundle peerTrust) {
    return PkiTls.builder()
        .identity(localIdentity)
        .trust(peerTrust)
        .peerPolicy(TlsPeerPolicy.withoutRevocationChecks())
        .build();
}
```

The TLS types are in `io.github.kaplaukhd.easypki.tls`. Identity is optional
for clients; explicit trust and peer policy are required. An explicitly empty
`TrustBundle` rejects all peer certificates. A `PkiSigner` alone is insufficient
for JSSE: the identity needs a JCA `PrivateKey` handle usable by the installed
providers. The adapter retains that handle without exporting it or changing
global provider/default SSL configuration.

For several named bundles, applications can declare `SslBundleRegistrar`
beans and call `registry.registerBundle(name, EasyPkiSslBundle.of(material))`.
The starter uses Boot's default registry without replacing other bundles;
duplicate names fail startup. If the application provides `SslBundles` or
`SslBundleRegistry`, automatic easy-pki registration backs off entirely and
the application owns registration. An application may also supply its own
`EasyPkiSslBundle` bean or replace the named `easyPkiSslBundleRegistrar` bean.

### Reload and container lifecycle

Keep the named bundle registered and update its original TLS context:

```java
applicationTls.reloadIdentity(replacementIdentity);
applicationTls.reloadTrust(replacementPeerTrust);
applicationTls.reload(replacementIdentity, replacementPeerTrust); // one generation
```

Preparation checks the candidate material before publication. A failed update
retains the active generation. New engines/sockets capture complete identity
and trust generations; existing connections and in-progress handshakes retain
their selected generation. Connection pools may reuse existing connections,
so publication does not forcibly reauthenticate them. Each successful reload
uses new underlying JSSE contexts and their session caches; see the TLS
module's contract for session and connection behavior.

Boot 3.3.5 normally configures Tomcat from stores, which bypasses custom
managers. The starter installs the live easy-pki context through Tomcat's public
connector hook for selected easy-pki bundles, including named SNI entries.
This integration requires Tomcat's JSSE implementation and rejects an explicitly
configured alternative implementation. It preserves the custom TLS peer policy,
including offline CRL checks, and lets new handshakes use reloaded material.
Tomcat remains optional for applications using only clients.

Use the context's reload methods instead of `SslBundleRegistry.updateBundle`.
The integration does not issue registry update events or promise transactional
updates across arbitrary Spring bundle consumers. `createSslContext()` returns
the live context; `getStores()` and `getManagers()` expose fixed snapshots at
the time of each call. Consumers retaining those snapshots need their own
refresh lifecycle. Automatic reload is tested with JSSE Tomcat and the Spring
REST client path above; other containers/backends require separate validation.

The existing monitor and health indicator continue to report their configured
PKCS#12 snapshots. They are not automatically switched to rotated TLS material.
The starter does not close application-owned key handles or contexts, and
changes to store files do not trigger reloads.

## Certificate expiry monitoring

Activate with `easy-pki.monitoring.enabled=true`. The starter registers
a `CertificateMonitor` that runs on its own daemon
`ScheduledExecutorService` — **no `@EnableScheduling` required**.

By default it monitors every configured trust anchor and every certificate in
the key-store chain. You can register additional certificates programmatically.

```java
@Component
public class ExtraCerts {
    public ExtraCerts(CertificateMonitor monitor) {
        monitor.register(externalCert, "external-partner");
    }
}
```

### Listening for events

```java
@Component
public class ExpiryAlerts {

    @EventListener
    public void onExpiring(CertExpiringEvent event) {
        log.warn("{} expires in {} days",
                 event.getAlias(), event.getDaysLeft());
    }

    @EventListener
    public void onExpired(CertExpiredEvent event) {
        alertService.page("Certificate " + event.getAlias() + " has expired");
    }
}
```

Events fire **at most once per state** per monitored certificate — a
server restarted 12 h later re-evaluates from scratch, but within a single
process lifetime an expiring cert won't flood your logs.

## Actuator health indicator

When `spring-boot-starter-actuator` is on the classpath and the health
endpoint is exposed, the starter contributes a `pki` component.

```json
{
  "status": "UP",
  "components": {
    "pki": {
      "status": "UP",
      "details": {
        "easyPkiTrustStore[0]": {
          "subject": "CN=Acme Root",
          "notAfter": "2035-01-01T00:00:00Z",
          "daysLeft": 3287,
          "status": "OK"
        },
        "easyPkiKeyStore[0]": {
          "subject": "CN=api.example.com",
          "notAfter": "2026-06-15T00:00:00Z",
          "daysLeft": 60,
          "status": "OK"
        }
      }
    }
  }
}
```

An expiring certificate stays `UP` but is marked `EXPIRING`. An expired
certificate turns the whole component `DOWN`.

## mTLS filter

When the Servlet API and Spring Web are on the classpath, the starter exposes
an `EasyPkiClientCertFilter` bean named `easyPkiClientCertFilter`. Its servlet
registration is **disabled by default**, so adding the starter does not reject
ordinary HTTP requests. To protect Spring Security routes, add the bean to
your `SecurityFilterChain`, typically before `X509AuthenticationFilter`.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
                                    EasyPkiClientCertFilter easyPki) throws Exception {
        return http
            .x509(x -> x.subjectPrincipalRegex("CN=(.*?)(?:,|$)"))
            .addFilterBefore(easyPki, X509AuthenticationFilter.class)
            .build();
    }
}
```

The filter:

- Extracts the chain from `jakarta.servlet.request.X509Certificate`.
- Validates it through `EasyPkiValidator`.
- Attaches the `ValidationResult` to the request under
  `easyPki.validationResult` for downstream diagnostics.
- Responds **401 Unauthorized** on failure; otherwise delegates to the
  next filter (where Spring Security's X509 auth takes over).

An optional mode (`new EasyPkiClientCertFilter(validator, true)`) passes
through requests without a client certificate instead of rejecting them.

For servlet applications that want container-level protection, explicitly
replace the named registration bean and choose the protected routes:

```java
@Bean(EasyPkiAutoConfiguration.SecurityConfiguration.FILTER_REGISTRATION_BEAN)
FilterRegistrationBean<EasyPkiClientCertFilter> clientCertificateRegistration(
        EasyPkiClientCertFilter filter) {
    FilterRegistrationBean<EasyPkiClientCertFilter> registration =
        new FilterRegistrationBean<>(filter);
    registration.addUrlPatterns("/protected/*");
    registration.setEnabled(true);
    return registration;
}
```

Choose either Spring Security insertion or servlet registration for a given
filter. Every bean declared as an `EasyPkiClientCertFilter`, including multiple
custom filters and filters marked `@Primary`, is excluded from automatic
servlet registration. Explicit application `FilterRegistrationBean`s retain
their enabled state and route mappings. With multiple filters, use a qualifier
when selecting the filter for a security chain or an explicit registration.

## Overriding beans

The validator, filter and monitor back off when an application supplies its own
bean of the same type. Qualified store beans and the filter registration back
off by their documented bean names. A custom `easyPkiTrustStore` bundle supplies
its `getChain()` unchanged to the validator, monitor and health indicator, even
when `easy-pki.trust-store.path` is also configured.

```java
@Bean
EasyPkiValidator easyPkiValidator(MyTrustStore ts) {
    return new EasyPkiValidator(
        ts.anchors(), ValidationMode.OCSP,
        Duration.ofSeconds(3), Duration.ofMinutes(10),
        Duration.ofSeconds(5), null);
}
```
