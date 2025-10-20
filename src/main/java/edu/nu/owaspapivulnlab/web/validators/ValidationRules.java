package edu.nu.owaspapivulnlab.web.validators;

/**
 * Task 9: Centralized input validation rules and ranges.

 */
public final class ValidationRules {
    private ValidationRules() {}

    // Numeric bounds
    public static final long MIN_ID = 1L;
    public static final long MAX_ID = Long.MAX_VALUE / 4; // defensive upper-bound

    // Money (demo): reject negative or excessively large transfers
    public static final String MIN_AMOUNT_STR = "0.01";
    public static final String MAX_AMOUNT_STR = "1000000"; // 1M cap for lab

    // Username / password
    public static final int USERNAME_MIN = 3;
    public static final int USERNAME_MAX = 50;
    public static final int PASSWORD_MIN = 8;
    public static final int PASSWORD_MAX = 128;
}
