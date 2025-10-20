package edu.nu.owaspapivulnlab.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Safe view of Account for API responses.
 * NOTE: Intentionally omits userId to avoid leaking ownership identifiers.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountDto {
    private Long id;
    private String name;     // if your Account has a name/label; ok if null
    private Double balance;  // demo balance (Double in this lab)

    public AccountDto() {}

    public AccountDto(Long id, String name, Double balance) {
        this.id = id;
        this.name = name;
        this.balance = balance;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public Double getBalance() { return balance; }

    public void setId(Long id) { this.id = id; }
    public void setName(String name) { this.name = name; }
    public void setBalance(Double balance) { this.balance = balance; }
}
