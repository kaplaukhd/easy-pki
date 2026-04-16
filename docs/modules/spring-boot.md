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

## Certificate expiry monitoring

Activate with `easy-pki.monitoring.enabled=true`. The starter registers
a `CertificateMonitor` that runs on its own daemon
`ScheduledExecutorService` — **no `@EnableScheduling` required**.

By default it monitors every certificate in the trust-store and key-store
chains. You can register additional certificates programmatically.

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

When `spring-security-web` is on the classpath, the starter registers an
`EasyPkiClientCertFilter` bean named `easyPkiClientCertFilter`. It's **not
added to the chain automatically** — wire it in explicitly, typically
before Spring Security's `X509AuthenticationFilter`.

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

## Overriding beans

Every auto-configured bean uses `@ConditionalOnMissingBean`, so defining
your own with the same type wins:

```java
@Bean
EasyPkiValidator easyPkiValidator(MyTrustStore ts) {
    return new EasyPkiValidator(
        ts.anchors(), ValidationMode.OCSP,
        Duration.ofSeconds(3), Duration.ofMinutes(10),
        Duration.ofSeconds(5), null);
}
```
