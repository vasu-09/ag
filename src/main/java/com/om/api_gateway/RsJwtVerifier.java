package com.om.api_gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RsJwtVerifier {

    private final GatewayRsConfig cfg;
    private final WebClient web;
    private final ObjectMapper om = new ObjectMapper();

    // simple in-memory JWKS cache
    private final ConcurrentHashMap<String, RSAPublicKey> byKid = new ConcurrentHashMap<>();
    private volatile long expiresAtMs = 0L;

    public RsJwtVerifier(GatewayRsConfig cfg) {
        this.cfg = cfg;
        this.web = WebClient.builder().build();
    }

    /** Public entry point used by JwtAuthFilter. */
    public Mono<Claims> validate(String token) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String kid = headerKid(jwt);
        if (kid == null || kid.isBlank()) {
            return Mono.error(new IllegalArgumentException("JWT missing kid"));
        }
        return keyForKid(kid)
                .flatMap(pub -> Mono.fromCallable(() -> parseAndValidate(jwt, pub)));
    }

    // ======================
    // == JWKS key lookup ==
    // ======================

    private Mono<RSAPublicKey> keyForKid(String kid) {
        long now = System.currentTimeMillis();
        RSAPublicKey k = byKid.get(kid);
        if (k != null && now < expiresAtMs) {
            return Mono.just(k);
        }
        return refreshJwks().then(Mono.justOrEmpty(byKid.get(kid)))
                .switchIfEmpty(Mono.error(new IllegalStateException("Unknown kid: " + kid)));
    }

    private Mono<Void> refreshJwks() {
        return web.get().uri(cfg.getJwkSetUri())
                .retrieve()
                .toEntity(Map.class)
                .doOnNext(this::updateCacheFromResponse)
                .then();
    }

    @SuppressWarnings("unchecked")
    private void updateCacheFromResponse(ResponseEntity<Map> resp) {
        Object keysObj = resp.getBody() == null ? null : resp.getBody().get("keys");
        if (!(keysObj instanceof List<?> keys)) return;

        Map<String, RSAPublicKey> tmp = new HashMap<>();
        for (Object o : keys) {
            if (!(o instanceof Map<?,?> jwk)) continue;
            String kty = String.valueOf(jwk.get("kty"));
            String use = String.valueOf(jwk.get("use"));
            String alg = String.valueOf(jwk.get("alg"));
            String kid = String.valueOf(jwk.get("kid"));
            if (!"RSA".equals(kty) || !"sig".equals(use) || !"RS256".equals(alg)) continue;
            String n = String.valueOf(jwk.get("n"));
            String e = String.valueOf(jwk.get("e"));
            tmp.put(kid, fromJwk(n, e));
        }
        if (!tmp.isEmpty()) {
            byKid.clear();
            byKid.putAll(tmp);
        }

        // TTL: from Cache-Control max-age if present; else 10 minutes
        long ttlMs = 10 * 60 * 1000L;
        List<String> cc = resp.getHeaders().getOrEmpty("Cache-Control");
        for (String h : cc) {
            for (String part : h.split(",")) {
                part = part.trim();
                if (part.startsWith("max-age=")) {
                    try { ttlMs = Long.parseLong(part.substring(8)) * 1000L; } catch (Exception ignore) {}
                }
            }
        }
        expiresAtMs = System.currentTimeMillis() + ttlMs;
    }

    private static RSAPublicKey fromJwk(String nB64u, String eB64u) {
        try {
            byte[] n = Base64.getUrlDecoder().decode(nB64u);
            byte[] e = Base64.getUrlDecoder().decode(eB64u);
            var kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(
                    new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e)));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to build RSAPublicKey from JWK", ex);
        }
    }

    // ============================
    // == JWT parsing/validation ==
    // ============================

    private Claims parseAndValidate(String token, RSAPublicKey pub) {
        Claims c = Jwts.parser()
                .verifyWith(pub)
                .requireIssuer(cfg.getIssuerUri())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Date exp = c.getExpiration();
        if (exp == null || exp.before(new Date())) {
            throw new JwtException("Expired");
        }
        return c;
    }

    /** Minimal header.kid extraction. */
    private String headerKid(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) return null;
        String json = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        try {
            Map<?, ?> m = om.readValue(json, Map.class);
            Object kid = m.get("kid");
            return kid == null ? null : kid.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
