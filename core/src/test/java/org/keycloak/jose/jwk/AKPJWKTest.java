package org.keycloak.jose.jwk;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.util.BouncyCastleSetup;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;

public class AKPJWKTest {

    @Rule
    public BouncyCastleSetup bc = new BouncyCastleSetup();

    @Test
    public void parseMLS_DSA_44() throws IOException {
        testDecodingAndEncodingPublicKey(Algorithm.ML_DSA_44);
    }

    @Test
    public void parseMLS_DSA_65() throws IOException {
        testDecodingAndEncodingPublicKey(Algorithm.ML_DSA_65);
    }

    @Test
    public void parseMLS_DSA_c() throws IOException {
        testDecodingAndEncodingPublicKey(Algorithm.ML_DSA_87);
    }

    private void testDecodingAndEncodingPublicKey(String algorithm) throws IOException {
        JWK jwk = getJwk(algorithm);

        PublicKey publicKey = JWKParser.create(jwk).toPublicKey();

        Assert.assertTrue(publicKey.getAlgorithm().startsWith("ML-DSA"));

        JWK akp = JWKBuilder.create().algorithm(algorithm).kid(jwk.getKeyId()).akp(publicKey);

        Assert.assertEquals(algorithm, akp.getAlgorithm());
        Assert.assertEquals(KeyType.AKP, akp.getKeyType());
        Assert.assertEquals(KeyUse.SIG.getSpecName(), akp.getPublicKeyUse());
        Assert.assertEquals(jwk.getKeyId(), akp.getKeyId());
        Assert.assertEquals(jwk.getOtherClaim(AKPPublicJWK.PUB, String.class), akp.getOtherClaim(AKPPublicJWK.PUB, String.class));
    }

    private JWK getJwk(String algorithm) throws IOException {
        InputStream inputStream = getClass().getResourceAsStream(algorithm.replace('-', '_') + ".jose.json");
        return JsonSerialization.readValue(inputStream, JWK.class);
    }

}
