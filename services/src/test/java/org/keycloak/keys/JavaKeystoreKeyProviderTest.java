/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.keys;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Optional;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.RealmModel;
import org.keycloak.vault.VaultCharSecret;
import org.keycloak.vault.VaultRawSecret;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Unit tests for {@link JavaKeystoreKeyProvider}.
 * Verifies that the KID for symmetric (OCT) keys is stable across multiple provider instantiations,
 * i.e. it does not generate a new random UUID on every load.
 *
 * Reproduces: https://github.com/keycloak/keycloak/issues/47495
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JavaKeystoreKeyProviderTest {

    private static final String KEYSTORE_PASSWORD = "keystorePassword";
    private static final String KEY_PASSWORD = "keyPassword";
    private static final String KEY_ALIAS = "hmac-test-key";

    private File keystoreFile;

    @BeforeAll
    void setUp() throws Exception {
        // Generate an HMAC-SHA512 SecretKey and store it in a JCEKS keystore
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
        keyGen.init(512);
        SecretKey secretKey = keyGen.generateKey();

        keystoreFile = Files.createTempFile("test-keystore", ".jceks").toFile();
        keystoreFile.deleteOnExit();

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(null, null);
        keyStore.setEntry(KEY_ALIAS, new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray()));
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    @AfterAll
    void tearDown() {
        if (keystoreFile != null) {
            keystoreFile.delete();
        }
    }

    @Test
    void hmacKeyKidShouldBeStableAcrossInstantiations() {
        ComponentModel model = buildComponentModel(Algorithm.HS512);

        // Simulate two separate provider instantiations (e.g., after restart or config change)
        String kid1 = loadKid(model);
        String kid2 = loadKid(model);

        assertNotNull(kid1, "KID must not be null");
        assertEquals(kid1, kid2,
                "KID for HMAC key must be stable across instantiations — a new random UUID must not be generated each time");
    }

    @Test
    void hmacKeyKidShouldMatchKeyFingerprint() {
        ComponentModel model = buildComponentModel(Algorithm.HS512);

        String kid = loadKid(model);

        // KID must not look like a random UUID (random UUIDs have hyphens and are 36 chars)
        // A fingerprint-based KID is a Base64url-encoded SHA-256 hash — no hyphens, length ~43
        assertNotNull(kid);
        assertEquals(false, kid.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
                "KID must be a deterministic fingerprint, not a random UUID. Got: " + kid);
    }

    private String loadKid(ComponentModel model) {
        // Remove cached note between instantiations to simulate a fresh provider load (e.g. after restart)
        model.removeNote(KeyWrapper.class.getName());

        JavaKeystoreKeyProvider provider = new JavaKeystoreKeyProvider(mockRealm(), model, mockVault());
        return provider.getKeysStream().findFirst()
                .map(KeyWrapper::getKid)
                .orElseThrow(() -> new AssertionError("No key returned from provider"));
    }

    private ComponentModel buildComponentModel(String algorithm) {
        ComponentModel model = new ComponentModel();
        model.setId("test-component-id");
        model.setProviderId(JavaKeystoreKeyProviderFactory.ID);

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(JavaKeystoreKeyProviderFactory.KEYSTORE_KEY, keystoreFile.getAbsolutePath());
        config.putSingle(JavaKeystoreKeyProviderFactory.KEYSTORE_TYPE_KEY, "JCEKS");
        config.putSingle(JavaKeystoreKeyProviderFactory.KEYSTORE_PASSWORD_KEY, KEYSTORE_PASSWORD);
        config.putSingle(JavaKeystoreKeyProviderFactory.KEY_ALIAS_KEY, KEY_ALIAS);
        config.putSingle(JavaKeystoreKeyProviderFactory.KEY_PASSWORD_KEY, KEY_PASSWORD);
        config.putSingle(Attributes.ALGORITHM_KEY, algorithm);
        config.putSingle(Attributes.ACTIVE_KEY, "true");
        config.putSingle(Attributes.ENABLED_KEY, "true");
        model.setConfig(config);

        return model;
    }

    private RealmModel mockRealm() {
        return null; // Not used by the provider for symmetric key loading
    }

    private VaultTranscriber mockVault() {
        // Plain-text passthrough vault — returns the value as-is (no vault lookup)
        return new VaultTranscriber() {
            @Override
            public VaultRawSecret getRawSecret(String value) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VaultCharSecret getCharSecret(String value) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VaultStringSecret getStringSecret(String value) {
                return new VaultStringSecret() {
                    @Override
                    public Optional<String> get() {
                        return Optional.of(value);
                    }

                    @Override
                    public void close() {
                    }
                };
            }
        };
    }
}
