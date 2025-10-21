package edu.nu.owaspapivulnlab.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests that verify the security fixes for Tasks 1..9 described in the README.
 *
 
 */
@SpringBootTest
@AutoConfigureMockMvc
public class SecurityFixesIntegrationTests {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private AppUserRepository userRepo;

    private final String TEST_PW = "StrongPass!23";

    @BeforeEach
    void clean() {
       
    }

    // --- Helpers --------------------------------

    private String randomIp() {
        int a = (int) (Math.random() * 254) + 1;
        int b = (int) (Math.random() * 254) + 1;
        int c = (int) (Math.random() * 254) + 1;
        int d = (int) (Math.random() * 254) + 1;
        return a + "." + b + "." + c + "." + d;
    }

    // Helper: create a user via signup (returns JSON response)
    private String signup(String username, String email, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "email", email,
                "password", password
        ));

        MvcResult r = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", randomIp())
                        .content(body))
                .andReturn();

        return r.getResponse().getContentAsString();
    }

    // Helper: login and return token string (uses random IP by default)
    private String loginAndGetToken(String username, String password) throws Exception {
        return loginAndGetToken(username, password, randomIp());
    }

    private String loginAndGetToken(String username, String password, String ip) throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", ip)
                        .content(body))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    // If login failed due to rate limit this will be visible here
                    assertThat(status).isEqualTo(200);
                })
                .andExpect(jsonPath("$.token").exists())
                .andReturn();

        JsonNode j = mapper.readTree(r.getResponse().getContentAsString());
        return j.get("token").asText();
    }

    // --- Tests ----------------------------------

    @Test
    void task1_passwords_are_bcrypt_encoded_on_signup() throws Exception {
        String username = "it_bcrypt_" + System.currentTimeMillis();
        String email = username + "@example.test";

        // signup uses its own random IP
        signup(username, email, TEST_PW);

        Optional<AppUser> uOpt = userRepo.findByUsername(username);
        assertThat(uOpt).isPresent();

        AppUser u = uOpt.get();
        assertThat(u.getPassword()).isNotBlank();

        // BCrypt hashes typically start with $2a$ or $2b$ or $2y$
        boolean looksLikeBcrypt = u.getPassword().startsWith("$2a$") ||
                u.getPassword().startsWith("$2b$") ||
                u.getPassword().startsWith("$2y$");
        assertThat(looksLikeBcrypt)
                .withFailMessage("Expected stored password to be BCrypt-hash; actual: %s", u.getPassword())
                .isTrue();
    }

    @Test
    void task2_api_paths_require_authentication() throws Exception {
        // example protected endpoint: accounts/mine (should be protected)
        mvc.perform(get("/api/accounts/mine")
                        .header("X-Forwarded-For", randomIp()))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    // Accept either 401 (unauthenticated) or 403 (access denied) depending on security config
                    assertThat(status).isIn(401, 403);
                });
    }

    @Test
    void task3_owner_only_account_access_forbidden() throws Exception {
        // Create a new user to act as attacker; use unique IPs
        String attacker = "it_attacker_" + System.currentTimeMillis();
        String attackerEmail = attacker + "@example.test";
        signup(attacker, attackerEmail, TEST_PW);
        String token = loginAndGetToken(attacker, TEST_PW);

        // seeded account id 2 exists (README seeds accounts). Calling another user's account should be forbidden.
        mvc.perform(get("/api/accounts/2/balance")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Forwarded-For", randomIp()))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    // Accept either 403 (Forbidden) or 404 (Not Found) as secure behaviour
                    assertThat(status).isIn(403, 404);
                });
    }

    @Test
    void task4_dtos_do_not_expose_sensitive_fields() throws Exception {
        // login as seeded alice (password per README: alice123)
        String token = loginAndGetToken("alice", "alice123");

        MvcResult r = mvc.perform(get("/api/accounts/mine")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Forwarded-For", randomIp()))
                .andExpect(status().isOk())
                .andReturn();

        String body = r.getResponse().getContentAsString();
        // Should not include sensitive fields like "password", "role", "isAdmin", "userId"
        assertThat(body).doesNotContain("\"password\"");
        assertThat(body).doesNotContain("\"role\"");
        assertThat(body).doesNotContain("\"isAdmin\"");
        assertThat(body).doesNotContain("userId");
    }

    @Test
    void task5_rate_limit_login_endpoint_enforced() throws Exception {
        // Use a fixed IP to intentionally trigger the rate limiter
        String ip = "203.0.113.10";
        String body = mapper.writeValueAsString(Map.of("username", "nope", "password", "bad"));

        // perform 5 tries => should be allowed (401 or 400 expected), on 6th expect 429
        for (int i = 1; i <= 5; i++) {
            mvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .header("X-Forwarded-For", ip)
                            .content(body))
                    .andExpect(result -> {
                        int status = result.getResponse().getStatus();
                        assertThat(status).isIn(401, 400);
                    });
        }

        // 6th attempt within same window -> should be rate limited (429)
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", ip)
                        .content(body))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status).isEqualTo(429);
                })
                .andExpect(jsonPath("$.error").exists())
                .andExpect(jsonPath("$.retryAfterSeconds").exists());
    }

    @Test
    void task6_mass_assignment_rejected_on_signup() throws Exception {
        // try to add role / isAdmin via signup payload -> unknown fields should cause 400
        String username = "it_mass_" + System.currentTimeMillis();
        String json = mapper.writeValueAsString(Map.of(
                "username", username,
                "email", username + "@example.test",
                "password", TEST_PW,
                "role", "ROLE_ADMIN",
                "isAdmin", true
        ));

        mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", randomIp())
                        .content(json))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status).isEqualTo(400);
                });
    }

    @Test
    void task7_jwt_includes_issuer_and_audience_and_has_ttl() throws Exception {
        // login a seeded user and inspect the token payload
        String token = loginAndGetToken("alice", "alice123");
        assertThat(token).isNotBlank();

        // JWT compact -> header.payload.signature
        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);

        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JsonNode payload = mapper.readTree(payloadJson);

        assertThat(payload.has("iss")).isTrue();
        assertThat(payload.has("aud")).isTrue();
        assertThat(payload.has("exp")).isTrue();

        long exp = payload.get("exp").asLong();
        long nowSec = System.currentTimeMillis() / 1000;
        assertThat(exp).isGreaterThan(nowSec);
        // sanity check: expiry should not be huge (e.g., > 1 hour)
        assertThat(exp - nowSec).isLessThanOrEqualTo(60 * 60L);
    }

    @Test
    void task8_error_responses_do_not_leak_stacktrace_or_internal_details() throws Exception {
        // Send malformed JSON which should trigger a 400 (or 429 if rate-limited)
        String badJson = "{ this-is-not: valid-json }";
        MvcResult r = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", randomIp())
                        .content(badJson))
                .andReturn();

        int status = r.getResponse().getStatus();
        // Prefer 400; if 429 appears it indicates rate-limiter still in play.
        assertThat(status).isIn(400, 429);

        String body = r.getResponse().getContentAsString();
        // If we got 400, ensure we didn't leak internals; if 429, it's rate-limited response and safe.
        if (status == 400) {
            assertThat(body.toLowerCase()).doesNotContain("stacktrace");
            assertThat(body).doesNotContain("Exception");
            assertThat(body).contains("error");
        } else {
            // rate-limited response should have structured JSON
            assertThat(body).contains("rate_limited");
        }
    }

    @Test
    void task9_transfer_negative_or_excessive_amount_validated() throws Exception {
        // sign up user and attempt a negative transfer
        String user = "it_transfer_" + System.currentTimeMillis();
        signup(user, user + "@x.test", TEST_PW);
        String token = loginAndGetToken(user, TEST_PW);

        String neg = "{\"fromAccountId\":1,\"toAccountId\":2,\"amount\":-50}";
        mvc.perform(post("/api/accounts/transfer")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .header("X-Forwarded-For", randomIp())
                        .content(neg))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status).isEqualTo(400);
                });

        String huge = String.format("{\"fromAccountId\":1,\"toAccountId\":2,\"amount\":%d}", 10_000_000);
        mvc.perform(post("/api/accounts/transfer")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .header("X-Forwarded-For", randomIp())
                        .content(huge))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status).isEqualTo(400);
                });
    }
}
