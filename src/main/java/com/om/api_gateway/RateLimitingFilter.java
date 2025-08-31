package com.om.api_gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple per-IP rate limiting filter based on a fixed window counter.
 */
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private final int maxRequests;
    private final long windowMillis;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitingFilter(@Value("${rate.limit.requests:60}") int maxRequests,
                              @Value("${rate.limit.window-seconds:60}") long windowSeconds) {
        this.maxRequests = maxRequests;
        this.windowMillis = windowSeconds * 1000L;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String key = resolveKey(exchange.getRequest());
        Window window = windows.computeIfAbsent(key, k -> new Window(windowMillis, maxRequests));
        if (!window.allow()) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            response.getHeaders().add("Content-Type", "application/json");
            response.getHeaders().add("Retry-After", String.valueOf(window.retryAfterSeconds()));
            byte[] body = "{\"error\":\"Too many requests\"}".getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
        }
        return chain.filter(exchange);
    }

    private String resolveKey(ServerHttpRequest request) {
        InetSocketAddress addr = request.getRemoteAddress();
        if (addr == null) {
            return "unknown";
        }
        return addr.getAddress().getHostAddress();
    }

    @Override
    public int getOrder() {
        return 0;
    }

    static class Window {
        private final long windowMillis;
        private final int maxRequests;
        private long windowStart;
        private int count;

        Window(long windowMillis, int maxRequests) {
            this.windowMillis = windowMillis;
            this.maxRequests = maxRequests;
            this.windowStart = System.currentTimeMillis();
            this.count = 0;
        }

        synchronized boolean allow() {
            long now = System.currentTimeMillis();
            if (now - windowStart >= windowMillis) {
                windowStart = now;
                count = 0;
            }
            if (count < maxRequests) {
                count++;
                return true;
            }
            return false;
        }

        synchronized long retryAfterSeconds() {
            long now = System.currentTimeMillis();
            long elapsed = now - windowStart;
            if (elapsed >= windowMillis) {
                return 0;
            }
            long remaining = windowMillis - elapsed;
            return (remaining + 999) / 1000; // ceil to next second
        }
    }
}