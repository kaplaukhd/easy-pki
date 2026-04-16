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
 * Spring Boot auto-configuration for easy-pki.
 *
 * <p>Binds {@code easy-pki.*} properties, loads configured PKCS#12 trust and
 * key stores, and exposes an {@code EasyPkiValidator} facade pre-wired with
 * trust anchors and the chosen revocation mode.
 */
package io.github.kaplaukhd.easypki.spring;
