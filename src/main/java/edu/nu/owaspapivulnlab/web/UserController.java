package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.security.CurrentUserService;
import edu.nu.owaspapivulnlab.web.dto.UserDto;
import edu.nu.owaspapivulnlab.web.dto.UpdateProfileRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;
    private final CurrentUserService current;
    private final PasswordEncoder encoder;

    public UserController(AppUserRepository users, CurrentUserService current, PasswordEncoder encoder) {
        this.users = users;
        this.current = current;
        this.encoder = encoder;
    }

    private static UserDto toDto(AppUser u) {
        return new UserDto(u.getId(), u.getUsername(), u.getEmail()); // Task 4 DTO (no password/role/isAdmin)
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        return current.current(auth)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(toDto(u)))
                .orElseGet(() -> ResponseEntity.status(401).body(Map.of("error","unauthenticated")));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable("id") Long id, Authentication auth) {
        Long callerId = current.currentUserId(auth).orElse(null);
        if (callerId == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        boolean isAdmin = current.hasRole(auth, "ADMIN");
        if (!isAdmin && !id.equals(callerId)) {
            return ResponseEntity.status(403).body(Map.of("error","forbidden"));
        }

        return users.findById(id)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(toDto(u)))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error","not_found")));
    }

    /**
     * Task 6: Safe self-update (no role/isAdmin allowed).
     * Accepts only email/password via UpdateProfileRequest; validation via annotations.
     */
    @PutMapping("/me")
    public ResponseEntity<?> updateMe(@Valid @RequestBody UpdateProfileRequest req, Authentication auth) {
        AppUser me = current.current(auth).orElse(null);
        if (me == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        // Whitelisted updates only:
        if (req.getEmail() != null) {
            me.setEmail(req.getEmail().trim());
        }
        if (req.getPassword() != null && !req.getPassword().isBlank()) {
            me.setPassword(encoder.encode(req.getPassword())); // server-side encode (no plaintext)
        }

        users.save(me);
        return ResponseEntity.ok(Map.of("status", "updated", "user", toDto(me)));
    }
}
