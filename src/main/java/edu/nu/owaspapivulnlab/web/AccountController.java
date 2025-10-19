package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.web.dto.TransferRequest;

import java.math.BigDecimal;
import java.util.*;

/**
 * Account endpoints hardened against BOLA/IDOR.
 * - Only the current user's accounts are visible
 * - Transfers require ownership of the source account
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    /** Helper: resolve current user from Authentication principal (username). */
    private AppUser me(Authentication auth) {
        if (auth == null || auth.getName() == null) return null;
        return users.findByUsername(auth.getName()).orElse(null);
    }

    /** View only MY accounts (ownership enforced). */
    @GetMapping("/mine")
    public List<Account> mine(Authentication auth) {
        AppUser m = me(auth);
        if (m == null) return Collections.emptyList();

        // FIX (Task 2): query is bound to the caller's userId
        return accounts.findByUserId(m.getId());
    }

    /** 
     * Optional: get ONE account by id, but only if I own it.
     * Shows strict user binding using findByIdAndUserId.
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> one(@PathVariable("id") Long id, Authentication auth) {  // <-- named path var
        try {
            AppUser m = me(auth);
            if (m == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));
                return accounts.findByIdAndUserId(id, m.getId())
                    .<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error","not_found")));
            } catch (Exception ex) {
        return ResponseEntity.status(500).body(Map.of("error", "server_error"));
            }
    }


    /**
     * Transfer between accounts.
     * - amount must be positive
     * - source account MUST belong to the current user (BOLA)
     * - both accounts must exist (to may be someone else's if business allows)
     * - money math via BigDecimal, entity uses Double
     */
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req, Authentication auth) {
        AppUser m = me(auth);
        if (m == null) {
            return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));
        }

        final Long fromId = req.getFromAccountId();
        final Long toId   = req.getToAccountId();
        final BigDecimal amount = req.getAmount();

        // Basic server-side validation for amount range (BigDecimal-safe)
        if (amount == null
                || amount.compareTo(new BigDecimal("0.01")) < 0
                || amount.compareTo(new BigDecimal("1000000")) > 0) {
            return ResponseEntity.badRequest().body(Map.of("error","invalid_amount"));
        }

        // FIX (Task 2): source account must be owned by the caller -> user-scoped lookup
        Account from = (fromId == null) ? null : accounts.findByIdAndUserId(fromId, m.getId()).orElse(null);

        // Destination account may be owned by anyone, depending on business rules.
        // If you want to restrict to self-only transfers, replace with findByIdAndUserId(toId, m.getId()).
        Account to = (toId == null) ? null : accounts.findById(toId).orElse(null);

        if (from == null || to == null) {
            return ResponseEntity.status(404).body(Map.of("error","account_not_found"));
        }

        // Sufficient funds?
        BigDecimal fromBal = BigDecimal.valueOf(from.getBalance() == null ? 0.0 : from.getBalance());
        if (fromBal.compareTo(amount) < 0) {
            return ResponseEntity.status(400).body(Map.of("error","insufficient_balance"));
        }

        // Money-safe math then persist as Double
        BigDecimal toBal = BigDecimal.valueOf(to.getBalance() == null ? 0.0 : to.getBalance());
        BigDecimal newFrom = fromBal.subtract(amount);
        BigDecimal newTo   = toBal.add(amount);

        from.setBalance(newFrom.doubleValue());
        to.setBalance(newTo.doubleValue());
        accounts.save(from);
        accounts.save(to);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "fromRemaining", newFrom
        ));
    }
}
