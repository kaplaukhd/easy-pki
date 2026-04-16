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
 * In-memory test helpers for easy-pki.
 *
 * <p>{@link io.github.kaplaukhd.easypki.test.TestPki} spins up a root CA and
 * (optionally) an intermediate CA in a few lines, issues leaf certificates on
 * demand, and exposes the resulting certificates, key pairs and CRL for use
 * in unit and integration tests. Consume this module with {@code scope=test}.
 */
package io.github.kaplaukhd.easypki.test;
