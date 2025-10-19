package edu.nu.owaspapivulnlab.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Task 5: Simple in-memory rate limiting with Bucket4j.
 *
 * Limits:
 *  - POST /api/auth/login      -> 5 req/min per IP
 *  - POST /api/auth/signup     -> 3 req/min per IP
 *  - POST /api/accounts/transfer -> 10 req/min per USER (subject), else per IP if unauthenticated
 *
 * NOTE: Per-instance memory. For production, use a distributed cache/store.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        // Decide the key + bandwidth for limited endpoints
        String key = null;
        Bandwidth limit = null;

        if ("POST".equalsIgnoreCase(method)) {
            if ("/api/auth/login".equals(path)) {
                key = "login:ip:" + clientIp(request); // 5/min per IP
                limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
            } else if ("/api/auth/signup".equals(path)) {
                key = "signup:ip:" + clientIp(request); // 3/min per IP
                limit = Bandwidth.classic(3, Refill.greedy(3, Duration.ofMinutes(1)));
            } else if ("/api/accounts/transfer".equals(path)) {
                String userKey = currentUserKey();
                if (userKey != null && !userKey.isBlank()) {
                    key = "transfer:user:" + userKey; // 10/min per user
                } else {
                    key = "transfer:ip:" + clientIp(request); // fallback per IP
                }
                limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
            }
        }

        // Not a limited endpoint → proceed
        if (key == null || limit == null) {
            chain.doFilter(request, response);
            return;
        }

        // Effectively-final var for lambda
        final Bandwidth bw = limit;

        // Get/create bucket and try to consume
        Bucket bucket = buckets.computeIfAbsent(key, k -> Bucket.builder().addLimit(bw).build());

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
            return;
        }

        // Too many requests → HTTP 429 + Retry-After
        long nanosToWait = bucket.getAvailableTokens() == 0
                ? Objects.requireNonNull(bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill())
                : 0L;

        long retryAfterSeconds = Duration.ofNanos(nanosToWait).toSeconds();
        if (retryAfterSeconds < 1) retryAfterSeconds = 1;

        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"rate_limited\",\"retryAfterSeconds\":" + retryAfterSeconds + "}");
    }

    /** Resolve client IP using X-Forwarded-For (if present) or remote address. */
    private String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0) ? xff.substring(0, comma).trim() : xff.trim();
        }
        return req.getRemoteAddr();
    }

    /** Current authenticated username (JWT subject); null if unauthenticated. */
    private String currentUserKey() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return null;
        String name = auth.getName();
        return (name == null || name.isBlank()) ? null : name;
    }
}
