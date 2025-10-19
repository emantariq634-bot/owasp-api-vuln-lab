package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

/**
 * Seeds required demo data on startup:
 *  - Users: alice (ROLE_USER), bob (ROLE_ADMIN)
 *  - Simple accounts for each (so transfer demos work)
 *
 * SECURITY:
 *  - Passwords are hashed with BCrypt via PasswordEncoder (no plaintext).
 *  - Uses upsert-style logic: creates records only if missing.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final AppUserRepository users;
    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(AppUserRepository users,
                      AccountRepository accounts,
                      PasswordEncoder passwordEncoder) {
        this.users = users;
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // --- Ensure ALICE exists ---
        AppUser alice = upsertUser(
                "alice",
                "alice@example.com",
                "alice123",         // NOTE: will be encoded with BCrypt
                "ROLE_USER"         // normal user
        );

        // --- Ensure BOB exists ---
        AppUser bob = upsertUser(
                "bob",
                "bob@example.com",
                "bob123",           // NOTE: will be encoded with BCrypt
                "ROLE_ADMIN"        // admin (needed for /api/admin/** endpoints)
        );

        // --- Ensure each has at least one account (simple balances for demo) ---
        upsertAccountForUser(alice.getId(), 1000.00);
        upsertAccountForUser(bob.getId(),   5000.00);
    }

    /**
     * Create user if missing; if present, leave as-is (idempotent).
     * Passwords are hashed with BCrypt (no plaintext storage).
     */
    private AppUser upsertUser(String username, String email, String rawPassword, String role) {
        Optional<AppUser> existing = users.findByUsername(username);
        if (existing.isPresent()) {
            return existing.get();
        }
        AppUser u = new AppUser();
        u.setUsername(username);
        u.setEmail(email);
        // BCrypt hash via injected PasswordEncoder bean from SecurityConfig
        u.setPassword(passwordEncoder.encode(rawPassword)); // <-- BCrypt hash, not plaintext
        u.setRole(role);                                    // <-- app uses hasRole("ADMIN") in SecurityConfig
        return users.save(u);
    }

    /**
     * Create a simple account for a user if they don't already have one.
     * Account entity uses userId + Double balance in this lab.
     */
    private void upsertAccountForUser(Long userId, Double initialBalance) {
        // If they already have any account, skip creating another
        if (!accounts.findByUserId(userId).isEmpty()) {
            return;
        }
        Account a = new Account();
        a.setUserId(userId);
        a.setBalance(initialBalance);
        accounts.save(a);
    }
}
