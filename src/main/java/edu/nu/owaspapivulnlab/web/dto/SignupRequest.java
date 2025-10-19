package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

// INLINE: No role/isAdmin fields here (Task 6: mass assignment prevention)
public record SignupRequest(
        @NotBlank @Size(min = 3, max = 40) String username,
        @NotBlank @Size(min = 8, max = 64) String password,
        @NotBlank @Email String email
) {}
