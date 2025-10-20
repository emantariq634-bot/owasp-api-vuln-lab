package edu.nu.owaspapivulnlab.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Adds/propagates a request correlation id:
 * - Reads X-Correlation-ID if present; otherwise generates a UUID.
 * - Stores in MDC as "cid" for logs and sets response header X-Correlation-ID.
 */
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String HEADER = "X-Correlation-ID";
    public static final String MDC_KEY = "cid";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String incoming = request.getHeader(HEADER);
        String cid = (incoming != null && !incoming.isBlank()) ? incoming : UUID.randomUUID().toString();

        MDC.put(MDC_KEY, cid);
        response.setHeader(HEADER, cid);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
