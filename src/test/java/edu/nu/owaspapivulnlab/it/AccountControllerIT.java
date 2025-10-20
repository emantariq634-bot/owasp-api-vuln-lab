package edu.nu.owaspapivulnlab.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
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

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AccountControllerIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @Autowired AppUserRepository users;
    @Autowired AccountRepository accounts;

    private String token;
    private Long userId;
    private Long fromId;
    private Long toId;

    @BeforeEach
    void setUp() throws Exception {
        String uname = "u" + System.currentTimeMillis();

        String signup = String.format(
            "{\"username\":\"%s\",\"email\":\"%s@test.com\",\"password\":\"StrongPass1\"}",
            uname, uname
        );
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(signup))
            .andExpect(status().isOk());

        AppUser u = users.findByUsername(uname).orElseThrow();
        userId = u.getId();

        Account aFrom = new Account();
        aFrom.setUserId(userId);
        aFrom.setBalance(5000.0);
        accounts.save(aFrom);
        fromId = aFrom.getId();

        Account aTo = new Account();
        aTo.setUserId(userId);
        aTo.setBalance(100.0);
        accounts.save(aTo);
        toId = aTo.getId();

        String login = String.format(
            "{\"username\":\"%s\",\"password\":\"StrongPass1\"}",
            uname
        );
        MvcResult res = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(login))
            .andExpect(status().isOk())
            .andReturn();

        JsonNode node = om.readTree(res.getResponse().getContentAsString(StandardCharsets.UTF_8));
        token = node.get("token").asText();
    }

    @Test
    void transfer_negative_amount_returns_400() throws Exception {
        String body = String.format(
            "{\"fromAccountId\":%d,\"toAccountId\":%d,\"amount\":-5}",
            fromId, toId
        );

        mvc.perform(post("/api/accounts/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error", anyOf(is("invalid_amount"), is("validation_error"), is("validation_failed"))));
    }

    @Test
    void transfer_excessive_amount_returns_400() throws Exception {
        String body = String.format(
            "{\"fromAccountId\":%d,\"toAccountId\":%d,\"amount\":10000000}",
            fromId, toId
        );

        mvc.perform(post("/api/accounts/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error", anyOf(is("invalid_amount"), is("validation_error"), is("validation_failed"))));
    }

    @Test
    void transfer_from_other_users_account_returns_403_or_404() throws Exception {
        Account foreign = new Account();
        foreign.setUserId(999999L);
        foreign.setBalance(50.0);
        accounts.save(foreign);

        String body = String.format(
            "{\"fromAccountId\":%d,\"toAccountId\":%d,\"amount\":10}",
            foreign.getId(), toId
        );

        mvc.perform(post("/api/accounts/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(result -> {
                int s = result.getResponse().getStatus();
                if (s != 403 && s != 404) {
                    throw new AssertionError("Expected 403 or 404 but was " + s
                        + " with body: " + result.getResponse().getContentAsString());
                }
            });
    }
}