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

/**
 * Core fluent API for PKI operations.
 *
 * <p>Entry points:
 * <ul>
 *   <li>{@code PkiKeys} — RSA and EC key pair generation</li>
 *   <li>{@code PkiCertificate} — fluent builders for self-signed and signed certificates</li>
 *   <li>{@code PkiCertificates} / {@code PkiPrivateKeys} — PEM/DER I/O</li>
 *   <li>{@code PkiPkcs12} — PKCS#12 keystore creation and loading</li>
 *   <li>{@code PkiCertInfo} — certificate inspection</li>
 *   <li>{@code PkiCrl} / {@code PkiCrls} — CRL generation and I/O</li>
 * </ul>
 */
package io.github.kaplaukhd.easypki;
