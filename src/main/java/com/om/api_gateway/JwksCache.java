package com.om.api_gateway;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class JwksCache {
    private final GatewayRsConfig cfg;
    private final RsaKeyUtil rsaUtil;
    private final WebClient web;
    private final ConcurrentHashMap<String, RSAPublicKey> byKid = new ConcurrentHashMap<>();
    private volatile long expiresAtMs = 0;

    public JwksCache(GatewayRsConfig cfg, RsaKeyUtil rsaUtil) {
        this.cfg = cfg; this.rsaUtil = rsaUtil;
        this.web = WebClient.builder().build();
    }

    public Mono<RSAPublicKey> getKey(String kid) {
        if (System.currentTimeMillis() > expiresAtMs) {
            return refresh().then(Mono.justOrEmpty(byKid.get(kid)));
        }
        RSAPublicKey k = byKid.get(kid);
        return k != null ? Mono.just(k) : refresh().then(Mono.justOrEmpty(byKid.get(kid)));
    }

    private Mono<Void> refresh() {
        return web.get().uri(cfg.getJwksUri())
                .retrieve()
                .toEntity(Map.class)
                .timeout(Duration.ofSeconds(3))
                .doOnNext(this::updateKeysFromResponse)
                .then();
    }

    @SuppressWarnings("unchecked")
    private void updateKeysFromResponse(ResponseEntity<Map> resp) {
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
            tmp.put(kid, rsaUtil.fromJwk(n, e));
        }
        byKid.clear(); byKid.putAll(tmp);

        long ttlMs = 10 * 60 * 1000L; // default 10m
        List<String> cc = resp.getHeaders().getOrEmpty("Cache-Control");
        for (String h : cc) {
            for (String part : h.split(",")) {
                part = part.trim();
                if (part.startsWith("max-age=")) {
                    try { ttlMs = Long.parseLong(part.substring(8)) * 1000L; } catch (Exception ignored) {}
                }
            }
        }
        expiresAtMs = System.currentTimeMillis() + ttlMs;
    }
}
