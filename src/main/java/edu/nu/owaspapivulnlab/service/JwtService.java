package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT service with hardened defaults.
 *
 * Properties (application.properties or env):
 *  - security.jwt.secret      : >= 32 chars (required)
 *  - security.jwt.issuer      : default "apilab"
 *  - security.jwt.audience    : default "apilab-clients"
 *  - security.jwt.ttlSeconds  : default 900 (15 minutes)
 *
 * Exposes:
 *  - issueToken(username, role)
 *  - validateAndGetSubjectAndRole(token)
 *
 * Throws IllegalArgumentException("invalid_or_expired_token") when validation fails.
 */
@Service
public class JwtService {

    private final String secretString;
    private final String issuer;
    private final String audience;
    private final long ttlSeconds;

    private SecretKey key;
    private JwtParser parser;

    public JwtService(
            @Value("${security.jwt.secret:}") String secretString,
            @Value("${security.jwt.issuer:apilab}") String issuer,
            @Value("${security.jwt.audience:apilab-clients}") String audience,
            @Value("${security.jwt.ttlSeconds:900}") long ttlSeconds
    ) {
        if (secretString == null || secretString.length() < 32) {
            throw new IllegalStateException(
                    "JWT secret must be at least 32 characters. " +
                    "Set property security.jwt.secret or env SECURITY_JWT_SECRET."
            );
        }
        this.secretString = secretString;
        this.issuer = issuer;
        this.audience = audience;
        this.ttlSeconds = ttlSeconds;
    }

    @PostConstruct
    void init() {
        // Build signing key & a strict parser once (avoid rebuilding on every call)
        this.key = Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
        this.parser = Jwts.parserBuilder()
                .requireIssuer(issuer)
                .requireAudience(audience)
                .setSigningKey(key)
                .build();
    }

    /**
     * Issue a compact JWT with subject=username and a "role" claim.
     * SECURITY: short TTL; explicit issuer & audience; HS256 with strong secret.
     */
    public String issueToken(String username, String role) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + (ttlSeconds * 1000));

        return Jwts.builder()
                .setSubject(username)
                .setIssuer(issuer)
                .setAudience(audience)
                .claim("role", role)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validate token signature, issuer, audience, and expiry.
     * Returns the subject (username) and role as a record.
     * Throws IllegalArgumentException("invalid_or_expired_token") on any failure.
     */
    public SubjectAndRole validateAndGetSubjectAndRole(String token) {
        try {
            Jws<Claims> jws = parser.parseClaimsJws(token);
            Claims claims = jws.getBody();

            String username = claims.getSubject();
            Object roleObj = claims.get("role");
            String role = (roleObj == null) ? null : String.valueOf(roleObj);

            if (username == null || username.isBlank() || role == null || role.isBlank()) {
                throw new IllegalArgumentException("invalid_or_expired_token");
            }
            return new SubjectAndRole(username, role);
        } catch (JwtException | IllegalArgumentException e) {
            // Any signature/format/expiry issue → treat as invalid
            throw new IllegalArgumentException("invalid_or_expired_token");
        }
    }

    /** Small DTO used by security filter to set Authentication authorities. */
    public record SubjectAndRole(String username, String role) {}
}
