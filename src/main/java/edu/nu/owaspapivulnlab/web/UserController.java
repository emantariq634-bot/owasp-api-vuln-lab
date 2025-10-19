package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.security.CurrentUserService;
import edu.nu.owaspapivulnlab.web.dto.UserDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;
    private final CurrentUserService current;

    public UserController(AppUserRepository users, CurrentUserService current) {
        this.users = users;
        this.current = current;
    }

    private static UserDto toDto(AppUser u) {
        return new UserDto(u.getId(), u.getUsername(), u.getEmail()); // No password/role/isAdmin
    }

    /** Current user's profile as safe DTO. */
    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        return current.current(auth)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(toDto(u)))
                .orElseGet(() -> ResponseEntity.status(401).body(Map.of("error","unauthenticated")));
    }

    /** Get user by id: self or admin only; returns DTO. */
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
}
