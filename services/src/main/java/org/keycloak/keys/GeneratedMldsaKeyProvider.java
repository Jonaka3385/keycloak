/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.jboss.logging.Logger;
import java.util.Base64;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.RealmModel;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GeneratedMldsaKeyProvider extends AbstractMldsaKeyProvider {
    private static final Logger logger = Logger.getLogger(GeneratedMldsaKeyProvider.class);

    public GeneratedMldsaKeyProvider(RealmModel realm, ComponentModel model) {
        super(realm, model);
    }

    @Override
    protected KeyWrapper loadKey(RealmModel realm, ComponentModel model) {
        String privateMldsaKeyBase64Encoded = model.getConfig().getFirst(GeneratedMldsaKeyProviderFactory.MLDSA_PRIVATE_KEY_KEY);
        String publicMldsaKeyBase64Encoded = model.getConfig().getFirst(GeneratedMldsaKeyProviderFactory.MLDSA_PUBLIC_KEY_KEY);

        byte[] rawPublicKeyBytes = Base64.getUrlDecoder().decode(publicMldsaKeyBase64Encoded);
        byte[] rawPrivateKeyBytes = Base64.getUrlDecoder().decode(privateMldsaKeyBase64Encoded);
        AlgorithmIdentifier algId = oid();

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, rawPublicKeyBytes);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
            System.out.println("Public Key created");

            // TODO private key encoding to be changed in future releases
            ASN1OctetString privateKeyOctetString = new DEROctetString(rawPrivateKeyBytes);
            PrivateKeyInfo pki = new PrivateKeyInfo(algId, privateKeyOctetString);
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));

            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            return createKeyWrapper(keyPair);
        } catch (Exception e) {
            logger.warnf("Exception at decodeMldsaPublicKey. %s", e.toString());
            return null;
        }
    }

    private AlgorithmIdentifier oid(){
        return switch (algorithm) {
            case "ML-DSA-44" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44);
            case "ML-DSA-65" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65);
            case "ML-DSA-87" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87);
            default -> throw new IllegalArgumentException("Invalid algorithm: " + algorithm);
        };
    }
}
