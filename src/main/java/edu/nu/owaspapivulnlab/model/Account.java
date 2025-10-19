package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import lombok.*;

/**
 * NOTE (Task 3 & 4): We store the owner as a plain userId to simplify
 * strict ownership checks and avoid exposing the full User entity.
 */
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Owner's user id (NOT a JPA relation, prevents over-fetch/exposure) */
    private Long userId;

    private String iban;

    /** Using Double to match the rest of the code paths in controllers */
    private Double balance;
}
