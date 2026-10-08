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
entry**, ordered by alias. Private-key entries and the certificates in their
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
