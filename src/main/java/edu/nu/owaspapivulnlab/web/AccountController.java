package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.security.CurrentUserService;
import edu.nu.owaspapivulnlab.web.dto.TransferRequest;
import edu.nu.owaspapivulnlab.web.dto.AccountDto;

import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Account endpoints hardened against BOLA/IDOR.
 * Task 4: return AccountDto to avoid leaking userId (ownership anchor) and other internals.
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

    /** Map entity -> safe DTO (no userId exposure). */
    private static AccountDto toDto(Account a) {
        // If your Account has 'name' field, include it; otherwise it's fine if null.
        return new AccountDto(a.getId(), /*a.getName()*/ null, a.getBalance());
    }

    /** View only MY accounts (ownership enforced) as DTOs. */
    @GetMapping("/mine")
    public List<AccountDto> mine(Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return Collections.emptyList();
        return accounts.findByUserId(uid).stream().map(AccountController::toDto).collect(Collectors.toList());
    }

    /**
     * Get ONE account by id (only if owned), returns DTO.
     * FIX from Task 2: explicit path var name; from Task 4: return DTO.
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> one(@PathVariable("id") Long id, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        return accounts.findByIdAndUserId(id, uid)
                .<ResponseEntity<?>>map(a -> ResponseEntity.ok(toDto(a)))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error","not_found")));
    }

    /**
     * Transfer between accounts (source must belong to caller).
     * Returns minimal info; do not include sensitive fields.
     */
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return ResponseEntity.status(401).body(Map.of("error","unauthenticated"));

        final Long fromId = req.getFromAccountId();
        final Long toId   = req.getToAccountId();
        final BigDecimal amount = req.getAmount();

        if (amount == null
                || amount.compareTo(new BigDecimal("0.01")) < 0
                || amount.compareTo(new BigDecimal("1000000")) > 0) {
            return ResponseEntity.badRequest().body(Map.of("error","invalid_amount"));
        }

        // Ownership enforcement (Task 2/3)
        Account from = (fromId == null) ? null : accounts.findByIdAndUserId(fromId, uid).orElse(null);
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

        // Task 4: return minimal safe payload (no userId)
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "fromAccount", toDto(from),
                "toAccount",   toDto(to)
        ));
    }
}
