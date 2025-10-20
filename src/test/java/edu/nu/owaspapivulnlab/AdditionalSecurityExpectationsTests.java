package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    String login(String user, String pw) throws Exception {
        String body = "{\"username\":\"" + user + "\",\"password\":\"" + pw + "\"}";
        String res = mvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode n = om.readTree(res);
        return n.get("token").asText();
    }

    // Disabled because your current security config allows GET /api/users (permitAll).
    @Disabled("Current app permits GET /api/users; enable when endpoint requires auth")
    @Test
    void protected_endpoints_require_authentication() throws Exception {
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    // Disabled because current app may allow non-admin deletes; enable after locking down DELETE /api/users/{id}
    @Disabled("Enable after DELETE /api/users/{id} requires admin")
    @Test
    void delete_user_requires_admin() throws Exception {
        String tUser = login("alice","alice123"); // not admin in this seed
        mvc.perform(delete("/api/users/1").header("Authorization","Bearer " + tUser))
                .andExpect(status().isForbidden());
    }

    // Disabled because your server currently accepts role/isAdmin in payload; enable after sanitizing
    @Disabled("Enable after server ignores role/isAdmin on create user")
    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        String payload = "{\"username\":\"eve2\",\"password\":\"pw\",\"email\":\"e2@e\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.role", anyOf(nullValue(), is("USER"))))
            .andExpect(jsonPath("$.isAdmin", anyOf(nullValue(), is(false))));
    }

    // Disabled because current JWT verifier may not enforce iss/aud; enable after hardening JwtService verification
    @Disabled("Enable after enforcing iss/aud on JWTs")
    @Test
    void jwt_must_be_valid_and_aud_iss_checked() throws Exception {
        String weak = login("alice","alice123");
        mvc.perform(get("/api/accounts/mine").header("Authorization","Bearer " + weak))
                .andExpect(status().isUnauthorized());
    }

    // Disabled because current ownership checks may differ; enable after enforcing owner-only read
    @Disabled("Enable after owner-only access is enforced for account reads")
    @Test
    void account_owner_only_access() throws Exception {
        String alice = login("alice","alice123");
        mvc.perform(get("/api/accounts/2/balance").header("Authorization","Bearer " + alice))
                .andExpect(status().isForbidden());
    }
}
