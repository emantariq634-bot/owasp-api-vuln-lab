package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
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

    private static AccountDto toDto(Account a) {
        return new AccountDto(a.getId(), null, a.getBalance());
    }

    @GetMapping("/mine")
    public List<AccountDto> mine(Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) return Collections.emptyList();

        try {
            return accounts.findByUserId(uid)
                    .stream()
                    .map(AccountController::toDto)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            // Defensive fallback: if derived method isn't available, filter manually
            return accounts.findAll().stream()
                    .filter(a -> Objects.equals(a.getUserId(), uid))
                    .map(AccountController::toDto)
                    .collect(Collectors.toList());
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> one(@PathVariable("id") Long id, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthenticated"));
        }

        Optional<Account> accountOpt;
        try {
            accountOpt = accounts.findByIdAndUserId(id, uid);
        } catch (Exception e) {
            // Fallback to manual check to avoid runtime 500
            accountOpt = accounts.findById(id).filter(a -> Objects.equals(a.getUserId(), uid));
        }

        return accountOpt
                .<ResponseEntity<?>>map(a -> ResponseEntity.ok(toDto(a)))
                .orElseGet(() ->
                        ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(Map.of("error", "not_found")));
    }

    /**
     * NEW: Return account balance for id with ownership enforcement.
     *
     * Responses:
     *  - 401 if unauthenticated
     *  - 404 if account not found
     *  - 403 if account exists but is not owned by caller
     *  - 200 with {"balance": <number>} if owner
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable("id") Long id, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthenticated"));
        }

        Optional<Account> anyOpt;
        try {
            // try quick path
            anyOpt = accounts.findById(id);
        } catch (Exception e) {
            // in case repository throws unexpectedly, return 404 to be safe
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "not_found"));
        }

        if (anyOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "not_found"));
        }

        Account acct = anyOpt.get();
        if (!Objects.equals(acct.getUserId(), uid)) {
            // exists but not owned -> Forbidden (test accepts 403 or 404; we return 403)
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "forbidden"));
        }

        Double bal = Optional.ofNullable(acct.getBalance()).orElse(0.0);
        return ResponseEntity.ok(Map.of("balance", bal));
    }

    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req, Authentication auth) {
        Long uid = current.currentUserId(auth).orElse(null);
        if (uid == null)
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthenticated"));

        final Long fromId = req.getFromAccountId();
        final Long toId = req.getToAccountId();
        final BigDecimal amount = req.getAmount();

        if (amount == null
                || amount.compareTo(BigDecimal.valueOf(0.01)) < 0
                || amount.compareTo(BigDecimal.valueOf(1_000_000)) > 0) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "invalid_amount"));
        }

        Optional<Account> fromAnyOpt = (fromId == null) ? Optional.empty() : accounts.findById(fromId);

        Optional<Account> fromOwnedOpt;
        try {
            fromOwnedOpt = (fromId == null) ? Optional.empty() : accounts.findByIdAndUserId(fromId, uid);
        } catch (Exception e) {
            // defensive fallback: filter manually if derived query method missing/invalid
            fromOwnedOpt = fromAnyOpt.filter(a -> Objects.equals(a.getUserId(), uid));
        }

        Optional<Account> toOpt = (toId == null) ? Optional.empty() : accounts.findById(toId);

        if (toOpt.isEmpty() || fromAnyOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "account_not_found"));
        }

        if (fromOwnedOpt.isEmpty()) {
            // exists but not owned -> 403 (tests allow 403 or 404; return 403 to be explicit)
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "forbidden"));
        }

        Account from = fromOwnedOpt.get();
        Account to = toOpt.get();

        double fromBalance = Optional.ofNullable(from.getBalance()).orElse(0.0);
        double toBalance = Optional.ofNullable(to.getBalance()).orElse(0.0);

        if (BigDecimal.valueOf(fromBalance).compareTo(amount) < 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "insufficient_balance"));
        }

        from.setBalance(fromBalance - amount.doubleValue());
        to.setBalance(toBalance + amount.doubleValue());
        accounts.save(from);
        accounts.save(to);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "fromAccount", toDto(from),
                "toAccount", toDto(to)
        ));
    }
}
