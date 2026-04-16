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
package io.github.kaplaukhd.easypki.test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@link TestPki} field or test-method parameter for injection by
 * {@link EasyPkiExtension}.
 *
 * <pre>{@code
 * @ExtendWith(EasyPkiExtension.class)
 * class MyTest {
 *     @InjectTestPki
 *     TestPki pki;
 *
 *     @Test
 *     void viaField() {
 *         X509Certificate cert = pki.issueCert().subject("CN=x").build();
 *     }
 *
 *     @Test
 *     void viaParameter(@InjectTestPki(withIntermediate = false) TestPki root) {
 *         // Simpler hierarchy: no intermediate CA.
 *     }
 * }
 * }</pre>
 *
 * <p>The extension creates a fresh {@link TestPki} for every target (field or
 * parameter) per test method — each test sees an isolated hierarchy.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.PARAMETER})
public @interface InjectTestPki {

    /** Whether to include an intermediate CA in the hierarchy. Default: {@code true}. */
    boolean withIntermediate() default true;

    /** Subject DN for the root CA. Default: {@code "CN=Test Root CA"}. */
    String rootSubject() default "CN=Test Root CA";

    /** Subject DN for the intermediate CA (if enabled). Default: {@code "CN=Test Issuing CA"}. */
    String intermediateSubject() default "CN=Test Issuing CA";
}
