package edu.nu.owaspapivulnlab.security;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Central helper to map the authenticated subject (username) -> AppUser / userId.
 * Controllers call this to enforce ownership checks (BOLA).
 */
@Component
public class CurrentUserService {

    private final AppUserRepository users;

    public CurrentUserService(AppUserRepository users) {
        this.users = users;
    }

    /** Returns the authenticated AppUser (or empty if unauthenticated/not found). */
    public Optional<AppUser> current(Authentication auth) {
        if (auth == null || auth.getName() == null) return Optional.empty();
        return users.findByUsername(auth.getName());
    }

    /** Returns the authenticated user's id (or empty). */
    public Optional<Long> currentUserId(Authentication auth) {
        return current(auth).map(AppUser::getId);
    }

    /** Convenience: true if the authenticated user has the given role (e.g., "ADMIN"). */
    public boolean hasRole(Authentication auth, String role) {
        if (auth == null || auth.getAuthorities() == null) return false;
        final String expected = "ROLE_" + role.toUpperCase();
        return auth.getAuthorities().stream().anyMatch(a -> expected.equals(a.getAuthority()));
    }
}
