package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.web.dto.LoginRequest;
import edu.nu.owaspapivulnlab.web.dto.SignupRequest;
import edu.nu.owaspapivulnlab.web.dto.TokenResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Task 1: Password Security
 * - Login verifies BCrypt (no plaintext compares).
 * - Signup hashes password with BCrypt before saving.
 * - Returns hardened JWT (Task 7 integration but safe here).
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(AppUserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        // reject duplicate username
        if (users.findByUsername(req.username()).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("error", "username_taken"));
        }

        // hash (BCrypt) then save
        AppUser u = new AppUser();
        u.setUsername(req.username());
        u.setEmail(req.email());
        u.setPassword(encoder.encode(req.password())); // <-- hash here
        u.setRole("ROLE_USER");                        // defensive default; no mass assignment
        users.save(u);

        // optional: auto-issue a token after signup
        String token = jwt.issueToken(u.getUsername(), u.getRole());
        return ResponseEntity.ok(new TokenResponse(token));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        AppUser u = users.findByUsername(req.username()).orElse(null);
        if (u == null || !encoder.matches(req.password(), u.getPassword())) {
            // generic error to avoid user enumeration
            return ResponseEntity.status(401).body(Map.of("error", "invalid_credentials"));
        }
        String token = jwt.issueToken(u.getUsername(), u.getRole());
        return ResponseEntity.ok(new TokenResponse(token));
    }
}
