package org.keycloak.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.rules.ExternalResource;

import java.security.Security;

public class BouncyCastleSetup extends ExternalResource {

    private boolean addedBc = false;

    @Override
    protected void after() {
        if (addedBc) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Override
    protected void before() throws Throwable {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            addedBc = true;
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
