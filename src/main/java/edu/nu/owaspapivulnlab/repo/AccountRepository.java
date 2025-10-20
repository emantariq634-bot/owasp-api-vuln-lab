package edu.nu.owaspapivulnlab.repo;

import edu.nu.owaspapivulnlab.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * Repository with user-scoped accessors to prevent IDOR/BOLA.
 * NOTE: Account entity has field 'userId' (Long).
 */
public interface AccountRepository extends JpaRepository<Account, Long> {

    /** All accounts owned by a given user. */
    List<Account> findByUserId(Long userId);

    /** A specific account by id, but ONLY if owned by userId. */
    Optional<Account> findByIdAndUserId(Long accountId, Long userId);
}
