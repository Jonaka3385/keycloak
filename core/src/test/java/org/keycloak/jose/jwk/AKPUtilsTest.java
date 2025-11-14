package org.keycloak.jose.jwk;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.util.BouncyCastleSetup;

import java.io.ByteArrayOutputStream;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class AKPUtilsTest {

    @Rule
    public BouncyCastleSetup bc = new BouncyCastleSetup();

    @Test
    public void testPrefixMLS_DSA_44() throws NoSuchAlgorithmException {
        testPrefix(Algorithm.ML_DSA_44);
    }

    @Test
    public void testPrefixMLS_DSA_65() throws NoSuchAlgorithmException {
        testPrefix(Algorithm.ML_DSA_65);
    }

    @Test
    public void testPrefixMLS_DSA_87() throws NoSuchAlgorithmException {
        testPrefix(Algorithm.ML_DSA_87);
    }

    private void testPrefix(String algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);

        byte[] bytes1 = kpg.generateKeyPair().getPublic().getEncoded();
        byte[] bytes2 = kpg.generateKeyPair().getPublic().getEncoded();
        byte[] bytes3 = kpg.generateKeyPair().getPublic().getEncoded();

        byte[] match1 = findMatchingPrefix(bytes1, bytes2);
        byte[] match2 = findMatchingPrefix(bytes1, bytes3);

        Assert.assertArrayEquals(AKPUtils.PREFIXES.get(algorithm), match1);
        Assert.assertArrayEquals(AKPUtils.PREFIXES.get(algorithm), match2);
    }

    private static byte[] findMatchingPrefix(byte[] a, byte[] b) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i < a.length && a[i] == b[i]; i++) {
            bos.write(a[i]);
        }
        return bos.toByteArray();
    }

}
