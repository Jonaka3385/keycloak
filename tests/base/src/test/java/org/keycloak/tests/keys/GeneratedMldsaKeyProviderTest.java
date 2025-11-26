/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.tests.keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.jose.jwk.AKPUtils;
import org.keycloak.keys.AbstractMldsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedRealm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@KeycloakIntegrationTest
public class GeneratedMldsaKeyProviderTest {

    @InjectRealm
    ManagedRealm realm;

    @Test
    public void verifyMldsa44() {
        verifyKeys("ML-DSA-44");
    }

    @Test
    public void verifyMldsa65() {
        verifyKeys("ML-DSA-65");
    }

    @Test
    public void verifyMldsa87() {
        verifyKeys("ML-DSA-87");
    }

    private void verifyKeys(String algorithm) {
        byte[] data = "Test".getBytes();

        KeyPair kp = AbstractMldsaKeyProviderFactory.generateMldsaKeyPair(algorithm);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());

        defaultKeysize(algorithm, kp.getPublic());

        byte[] signature = sign(algorithm, data, kp.getPrivate());
        assertNotNull(signature);

        try {
            boolean success = verify(algorithm, signature, data, kp.getPublic());
            assertTrue(success);
        } catch (Exception e) {
            fail("Signature verification failed");
        }
    }

    private byte[] sign(String algorithm, byte[] data, PrivateKey privateKey) {
        byte[] signature;
        try {
            Signature signer = Signature.getInstance(algorithm, "BC");
            signer.initSign(privateKey);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception e) {
            fail(e.getMessage());
            return null;
        }
        return signature;
    }

    private boolean verify(String algorithm, byte[] signature, byte[] data, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance(algorithm, "BC");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    protected ComponentRepresentation createRep(String name, String providerId) {
        ComponentRepresentation rep = new ComponentRepresentation();
        rep.setName(name);
        rep.setParentId(realm.admin().toRepresentation().getId());
        rep.setProviderId(providerId);
        rep.setProviderType(KeyProvider.class.getName());
        rep.setConfig(new MultivaluedHashMap<>());
        return rep;
    }

    private void defaultKeysize(String algorithm, PublicKey publicKey) {
        byte[] reDecoded = Base64.getUrlDecoder().decode(AKPUtils.toEncodedPub(publicKey, algorithm));
        assertEquals(mldsaLength(algorithm), reDecoded.length);
    }

    protected int mldsaLength(String algorithm) {
        return switch (algorithm) {
            case "ML-DSA-44" -> 1312;
            case "ML-DSA-65" -> 1952;
            case "ML-DSA-87" -> 2592;
            default -> -1;
        };
    }
}
