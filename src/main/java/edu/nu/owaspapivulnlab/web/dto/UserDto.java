package edu.nu.owaspapivulnlab.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Safe view of AppUser for API responses.
 * DO NOT expose password, role, isAdmin.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {
    private Long id;
    private String username;
    private String email;

    public UserDto() {}

    public UserDto(Long id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }

    public void setId(Long id) { this.id = id; }
    public void setUsername(String username) { this.username = username; }
    public void setEmail(String email) { this.email = email; }
}
