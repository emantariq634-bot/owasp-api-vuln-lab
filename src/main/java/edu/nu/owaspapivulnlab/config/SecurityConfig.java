package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;   // <-- new
import org.springframework.security.crypto.password.PasswordEncoder;     // <-- new
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

/**
 * Spring Security config (no preview features).
 * - Stateless JWT auth
 * - Admin guard for /api/admin/**
 * - Simple fixed-window rate limiter (demo)
 */
@Configuration
public class SecurityConfig {

    private final JwtService jwt;

    public SecurityConfig(JwtService jwt) {
        this.jwt = jwt;
    }

    /** 
     * BCrypt PasswordEncoder bean so Spring can inject it (e.g., in DataSeeder, AuthController).
     * SECURITY: Never store plaintext passwords.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(h -> h.frameOptions(f -> f.disable())) // allow H2 console in dev
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/signup").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // Order matters: rate limit first, then JWT auth
            .addFilterBefore(new SimpleRateLimitFilter(60, 30), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new JwtAuthFilter(jwt), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /** Very small demo rate limiter (fixed window, per remote IP). */
    static class SimpleRateLimitFilter extends OncePerRequestFilter {
        private final int windowSeconds;
        private final int maxRequests;
        private final Map<String, Deque<Long>> buckets = new HashMap<>();

        SimpleRateLimitFilter(int windowSeconds, int maxRequests) {
            this.windowSeconds = windowSeconds;
            this.maxRequests = maxRequests;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {

            final String path = req.getRequestURI();

            // ✅ FIX: apply rate limiting ONLY to sensitive auth endpoints.
            // This prevents 429s on normal app traffic (H2 console, accounts, admin, etc.).
            boolean isAuthEndpoint =
                    "/api/auth/login".equals(path)
                 || "/api/auth/signup".equals(path);

            if (!isAuthEndpoint) {
                // Not an auth endpoint -> skip rate limit
                chain.doFilter(req, res);
                return;
            }

            String key = Optional.ofNullable(req.getRemoteAddr()).orElse("unknown");
            long now = Instant.now().getEpochSecond();

            synchronized (buckets) {
                buckets.putIfAbsent(key, new ArrayDeque<>());
                Deque<Long> q = buckets.get(key);

                // Evict old entries that are outside the window
                while (!q.isEmpty() && (now - q.peekFirst()) >= windowSeconds) {
                    q.pollFirst();
                }

                // Enforce limit for this IP within the window
                if (q.size() >= maxRequests) {
                    // 429 Too Many Requests
                    res.setStatus(429);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"rate_limited\"}");
                    return;
                }

                // Record this request timestamp
                q.addLast(now);
            }

            chain.doFilter(req, res);
        }
    }

    /** Extracts Bearer token, validates with JwtService, and populates SecurityContext. */
    static class JwtAuthFilter extends OncePerRequestFilter {
        private final JwtService jwt;

        JwtAuthFilter(JwtService jwt) {
            this.jwt = jwt;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            String auth = req.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    var sar = jwt.validateAndGetSubjectAndRole(token);
                    var authentication = new UsernamePasswordAuthenticationToken(
                            sar.username(), null, List.of(new SimpleGrantedAuthority(sar.role())));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (IllegalArgumentException ignored) {
                    // invalid/expired token -> leave unauthenticated; downstream will reject
                }
            }
            chain.doFilter(req, res);
        }
    }
}
