
package edu.nu.owaspapivulnlab.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    @Test
    void signup_then_login_success() throws Exception {
        String uname = "eman" + System.currentTimeMillis();
        String body = """
            { "username":"%s", "email":"%s@test.com", "password":"StrongPass1" }
        """.formatted(uname, uname);

        mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("registered")));

        // login
        String login = """
            { "username":"%s", "password":"StrongPass1" }
        """.formatted(uname);

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(login))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()));
    }

    @Test
    void signup_short_password_returns_400_validation() throws Exception {
        String body = """
            { "username":"emanShort", "email":"emanShort@test.com", "password":"123" }
        """;
        mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                // accept either validation_error or validation_failed
                .andExpect(jsonPath("$.error", anyOf(is("validation_error"), is("validation_failed"))));
    }
}


>>>>>>> 2a9328f22396125f4357df3e4fe535118f20c0b4
