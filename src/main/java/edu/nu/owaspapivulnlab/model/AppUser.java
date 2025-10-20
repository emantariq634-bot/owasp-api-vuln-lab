package edu.nu.owaspapivulnlab.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

/**
 * User entity.
 * SECURITY: Mark sensitive fields with @JsonIgnore so they never appear in JSON responses,
 * even if someone accidentally returns the entity. Prefer returning DTOs (see later tasks).
 */
@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    @JsonIgnore                // <-- prevent password from being serialized
    @NotBlank
    private String password;

    @JsonIgnore                // <-- prevent role/isAdmin leaking
    private String role;       // "ROLE_USER" or "ROLE_ADMIN"

    @JsonIgnore
    private boolean isAdmin;

    @Email
    private String email;
}
