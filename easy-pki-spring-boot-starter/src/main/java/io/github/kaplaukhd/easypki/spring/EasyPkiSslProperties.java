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
package io.github.kaplaukhd.easypki.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Opt-in SSL bundle registration, separate from the existing validator settings.
 * An application-provided TLS context already owns its peer policy. Otherwise
 * supply a TlsPeerPolicy bean or explicitly select {@code revocation-mode=disabled}.
 *
 * @param bundleName nonblank name registered in Spring's default SSL bundle registry
 * @param revocationMode explicit revocation choice, with no default
 */
@ConfigurationProperties("easy-pki.ssl")
public record EasyPkiSslProperties(String bundleName, RevocationMode revocationMode) {
    /** Property choices; applications needing CRLs supply a TlsPeerPolicy bean. */
    public enum RevocationMode {
        /** Explicitly disable TLS revocation checking while retaining peer validation. */
        DISABLED
    }
}
