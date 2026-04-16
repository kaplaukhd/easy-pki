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
 * Certificate chain validation and revocation checking.
 *
 * <p>Entry points:
 * <ul>
 *   <li>{@link io.github.kaplaukhd.easypki.validation.CertValidator} — fluent
 *       builder for chain and revocation validation</li>
 *   <li>{@link io.github.kaplaukhd.easypki.validation.ValidationResult} —
 *       immutable outcome with {@code isValid}, {@code isExpired},
 *       {@code isRevoked}, error list, and built chain</li>
 * </ul>
 */
package io.github.kaplaukhd.easypki.validation;
