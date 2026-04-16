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

import java.lang.reflect.Field;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

/**
 * JUnit 5 extension that injects a fresh {@link TestPki} into every field
 * and parameter annotated with {@link InjectTestPki}.
 *
 * <pre>{@code
 * @ExtendWith(EasyPkiExtension.class)
 * class MyTest {
 *     @InjectTestPki
 *     TestPki pki;   // new PKI per test method
 * }
 * }</pre>
 *
 * <p>One {@link TestPki} is created per target per test method. Fields are
 * assigned before each test runs via reflection; method parameters are
 * resolved on demand. Callers are responsible for closing any OCSP
 * responders they start.
 */
public final class EasyPkiExtension implements BeforeEachCallback, ParameterResolver {

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        Object testInstance = context.getRequiredTestInstance();
        Class<?> type = testInstance.getClass();
        // Walk the class hierarchy so base-class fields are populated too.
        while (type != null && type != Object.class) {
            for (Field field : type.getDeclaredFields()) {
                InjectTestPki annotation = field.getAnnotation(InjectTestPki.class);
                if (annotation == null) {
                    continue;
                }
                if (!TestPki.class.isAssignableFrom(field.getType())) {
                    throw new IllegalStateException(
                            "@InjectTestPki field '" + field.getName()
                                    + "' must be of type TestPki, got " + field.getType().getName());
                }
                field.setAccessible(true);
                field.set(testInstance, buildPki(annotation));
            }
            type = type.getSuperclass();
        }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext,
                                     ExtensionContext extensionContext)
            throws ParameterResolutionException {
        return parameterContext.isAnnotated(InjectTestPki.class)
                && TestPki.class.isAssignableFrom(parameterContext.getParameter().getType());
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext,
                                   ExtensionContext extensionContext)
            throws ParameterResolutionException {
        InjectTestPki annotation = parameterContext
                .findAnnotation(InjectTestPki.class)
                .orElseThrow(() -> new ParameterResolutionException(
                        "Missing @InjectTestPki on parameter"));
        return buildPki(annotation);
    }

    private static TestPki buildPki(InjectTestPki annotation) {
        TestPkiBuilder builder = TestPki.create()
                .withRootCa(annotation.rootSubject());
        if (annotation.withIntermediate()) {
            builder.withIntermediateCa(annotation.intermediateSubject());
        }
        return builder.build();
    }
}
