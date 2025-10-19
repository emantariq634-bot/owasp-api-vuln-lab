package edu.nu.owaspapivulnlab.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Task 6: Explicit DTO without role/isAdmin; unknown fields are rejected (global) and ignored here as a belt-and-suspenders.
 */
@JsonIgnoreProperties(ignoreUnknown = false) // with global fail-on-unknown=true, unknown keys will trigger 400
public class SignupRequest {

    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Email
    @Size(max = 120)
    private String email;

    @NotBlank
    @Size(min = 8, max = 128)
    private String password;

    public SignupRequest() {}
    public SignupRequest(String username, String email, String password) {
        this.username = username; this.email = email; this.password = password;
    }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public void setUsername(String username) { this.username = username; }
    public void setEmail(String email) { this.email = email; }
    public void setPassword(String password) { this.password = password; }
}
