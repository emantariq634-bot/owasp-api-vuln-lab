package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.security.CurrentUserService;
import edu.nu.owaspapivulnlab.web.dto.TransferRequest;

import java.math.BigDecimal;
import java.util.*;

/**
 * Account endpoints hardened against BOLA/IDOR.
 * Task 3: centralizes subject->userId mapping via CurrentUserService, validates ownership before work.
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final CurrentUserService current;

    public AccountController(AccountRepository accounts,
                             AppUserRepository users,
                             CurrentUserService current) {
        this.accounts = accounts;
        this.users = users;
        this.current = current;
    }

    /** View only MY accounts (ownership enforced). */
    @GetMapping("/mine")
    public List<Account> mine(Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return Collections.emptyList();
        return accounts.findByUserId(uid); // user-scoped repository
    }

    /**
     * Get ONE account by id, but only if I own it.
     * FIX: name @PathVariable to avoid '-parameters' requirement.
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> one(@PathVariable("id") Long id, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        return accounts.findByIdAndUserId(id, uid)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error","not_found")));
    }

    /**
     * Transfer between accounts.
     * Ownership rule: source 'from' MUST be owned by the caller.
     * (You can optionally restrict 'to' to self as well by swapping to findByIdAndUserId.)
     */
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        final Long fromId = req.getFromAccountId();
        final Long toId   = req.getToAccountId();
        final BigDecimal amount = req.getAmount();

        // Basic BigDecimal validation
        if (amount == null
                || amount.compareTo(new BigDecimal("0.01")) < 0
                || amount.compareTo(new BigDecimal("1000000")) > 0) {
            return ResponseEntity.badRequest().body(Map.of("error","invalid_amount"));
        }

        // Enforce ownership of 'from'
        Account from = (fromId == null) ? null : accounts.findByIdAndUserId(fromId, uid).orElse(null);
        // Destination may be anyone’s account (business rule); restrict if needed.
        Account to   = (toId   == null) ? null : accounts.findById(toId).orElse(null);

        if (from == null || to == null) {
            return ResponseEntity.status(404).body(Map.of("error","account_not_found"));
        }

        BigDecimal fromBal = BigDecimal.valueOf(from.getBalance() == null ? 0.0 : from.getBalance());
        if (fromBal.compareTo(amount) < 0) {
            return ResponseEntity.status(400).body(Map.of("error","insufficient_balance"));
        }

        BigDecimal toBal = BigDecimal.valueOf(to.getBalance() == null ? 0.0 : to.getBalance());
        BigDecimal newFrom = fromBal.subtract(amount);
        BigDecimal newTo   = toBal.add(amount);

        from.setBalance(newFrom.doubleValue());
        to.setBalance(newTo.doubleValue());
        accounts.save(from);
        accounts.save(to);

        return ResponseEntity.ok(Map.of("status","ok","fromRemaining", newFrom));
    }
}
