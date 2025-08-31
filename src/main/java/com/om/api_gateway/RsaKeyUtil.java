package com.om.api_gateway;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@Component
public class RsaKeyUtil {
    public RSAPublicKey fromJwk(String nB64u, String eB64u) {
        byte[] n = Base64.getUrlDecoder().decode(nB64u);
        byte[] e = Base64.getUrlDecoder().decode(eB64u);
        try {
            var kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(
                    new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e))
            );
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to build RSAPublicKey from JWK", ex);
        }
    }
}