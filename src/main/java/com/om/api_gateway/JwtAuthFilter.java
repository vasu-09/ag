package com.om.api_gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Date;

//@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final RsJwtVerifier verifier;
    private static final Logger audit = LoggerFactory.getLogger("AUDIT");



    public JwtAuthFilter(RsJwtVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var request = exchange.getRequest();
        var path = request.getURI().getPath();
        var method = request.getMethod() == null ? "" : request.getMethod().name();
        var ip = clientIp(request);

        // 1) Allow preflight and public routes
        if (request.getMethod() == HttpMethod.OPTIONS) {
            return filterAndLog(exchange, chain, "-", path, method, ip);
        }
        if (path.startsWith("/auth/")
                || path.startsWith("/public/")
                || path.startsWith("/.well-known/")
                || path.startsWith("/actuator/")) {
            return filterAndLog(exchange, chain, "-", path, method, ip);
        }

        // 2) Extract bearer
        String auth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.startsWith("Bearer ")) {
            return Mono.error(
                    new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization header missing"));
        }
        String token = auth.substring(7);

        // 3) Verify RS256 via JWKS and forward select claims as headers
        return verifier.validate(token)
                .flatMap(claims -> validateClaims(claims)
                        .flatMap(valid -> {
                    String sub = claims.getSubject();
                    Object userId = claims.get("userId");
                    String user = userId == null ? (sub == null ? "" : sub) : String.valueOf(userId);
                    ServerHttpRequest mutated = request.mutate()
                            .header("X-User-Sub", sub == null ? "" : sub)
                            .header("X-User-Id", userId == null ? "" : String.valueOf(userId))
                            .build();
                    return chain.filter(exchange.mutate().request(mutated).build())
                            .doOnSuccess(v -> logAudit(user, path, method, ip, exchange, null))
                            .doOnError(err -> logAudit(user, path, method, ip, exchange, err.getMessage()));
                })
                .onErrorResume(e -> Mono.error(
                        new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                                "Invalid token: " + e.getMessage()))));
    }



private Mono<Claims> validateClaims(Claims claims) {
    Date exp = claims.getExpiration();
    if (exp == null || exp.before(new Date())) {
        return Mono.error(new JwtException("Expired"));
    }
    return Mono.just(claims);
}

    private Mono<Void> filterAndLog(ServerWebExchange exchange, GatewayFilterChain chain,
                                    String user, String path, String method, String ip) {
        return chain.filter(exchange)
                .doOnSuccess(v -> logAudit(user, path, method, ip, exchange, null))
                .doOnError(err -> logAudit(user, path, method, ip, exchange, err.getMessage()));
    }

    private void logAudit(String user, String path, String method, String ip, ServerWebExchange exchange, String msg) {
        int status = exchange.getResponse().getStatusCode() == null ? 0
                : exchange.getResponse().getStatusCode().value();
        logAudit(user, path, method, ip, status, msg);
    }


    private Mono<Void> auditOnError(ServerWebExchange exchange, String user, String path,
                                    String method, String ip, String err, HttpStatus status) {
        logAudit(user, path, method, ip, status.value(), err);
        return errorResponse(exchange, err, status);
    }

    private Mono<Void> errorResponse(ServerWebExchange exchange, String err, HttpStatus status) {
        var res = exchange.getResponse();
        res.setStatusCode(status);
        res.getHeaders().add("Content-Type", "application/json");
        byte[] body = ("{\"error\":\"" + err + "\"}").getBytes(StandardCharsets.UTF_8);
        return res.writeWith(Mono.just(res.bufferFactory().wrap(body)));
    }
    private void logAudit(String user, String path, String method, String ip, int status, String msg) {
        String ts = Instant.now().toString();
        if (status == HttpStatus.TOO_MANY_REQUESTS.value()) {
            audit.warn("ts={} user={} ip={} method={} path={} status={} msg={}",
                    ts, user, ip, method, path, status, msg);
        } else if (status >= 400) {
            audit.warn("ts={} user={} ip={} method={} path={} status={} msg={}",
                    ts, user, ip, method, path, status, msg);
        } else {
            audit.info("ts={} user={} ip={} method={} path={} status={} msg={}",
                    ts, user, ip, method, path, status, msg);
        }
    }

    private String clientIp(ServerHttpRequest request) {
        String xf = request.getHeaders().getFirst("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddress() == null ? "unknown"
                : request.getRemoteAddress().getAddress().getHostAddress();
    }


    @Override
    public int getOrder() {
        return -1;
    }

}
