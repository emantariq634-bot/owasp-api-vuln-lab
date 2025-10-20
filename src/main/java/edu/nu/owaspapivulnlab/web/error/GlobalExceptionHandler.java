package edu.nu.owaspapivulnlab.web.error;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import edu.nu.owaspapivulnlab.logging.RequestCorrelationFilter;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * Production-safe error responses with correlation id.
 * Detailed messages are hidden unless app.errors.expose-details=true.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @Value("${app.errors.expose-details:false}")
    private boolean exposeDetails;

    private String cid() {
        String cid = MDC.get(RequestCorrelationFilter.MDC_KEY);
        return cid == null ? "n/a" : cid;
    }

    /** Build a Map<String,Object> payload consistently (avoids generics inference issues). */
    private Map<String, Object> payload(String code, String message) {
        Map<String, Object> m = new HashMap<>();
        m.put("error", code);
        m.put("correlationId", cid());
        if (exposeDetails && message != null && !message.isBlank()) {
            m.put("message", message);
        }
        return m;
    }

    private ResponseEntity<Map<String, Object>> respond(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(payload(code, message));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> badJson(HttpMessageNotReadableException ex) {
        String kind = (ex.getCause() instanceof InvalidFormatException) ? "invalid_json_value" : "malformed_json";
        log.warn("400 {} cid={} cause={}", kind, cid(), ex.toString(), ex);
        return respond(HttpStatus.BAD_REQUEST, "bad_request", ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> validation(MethodArgumentNotValidException ex) {
        log.warn("400 validation_failed cid={} fields={}", cid(), ex.getBindingResult().getFieldErrors(), ex);
        return respond(HttpStatus.BAD_REQUEST, "validation_failed", ex.getMessage());
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> constraint(ConstraintViolationException ex) {
        log.warn("400 constraint_violation cid={} violations={}", cid(), ex.getConstraintViolations(), ex);
        return respond(HttpStatus.BAD_REQUEST, "validation_failed", ex.getMessage());
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> missingParam(MissingServletRequestParameterException ex) {
        log.warn("400 missing_param cid={} {}", cid(), ex.getMessage(), ex);
        return respond(HttpStatus.BAD_REQUEST, "bad_request", ex.getMessage());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> unauthorized(AuthenticationException ex) {
        log.warn("401 unauthorized cid={} {}", cid(), ex.getMessage(), ex);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .headers(headers)
                .body(payload("unauthorized", ex.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> forbidden(AccessDeniedException ex) {
        log.warn("403 forbidden cid={} {}", cid(), ex.getMessage(), ex);
        return respond(HttpStatus.FORBIDDEN, "forbidden", null);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> method(HttpRequestMethodNotSupportedException ex) {
        log.warn("405 method_not_allowed cid={} {}", cid(), ex.getMessage(), ex);
        return respond(HttpStatus.METHOD_NOT_ALLOWED, "method_not_allowed", null);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException ex) {
        log.warn("400 illegal_argument cid={} {}", cid(), ex.getMessage(), ex);
        return respond(HttpStatus.BAD_REQUEST, "bad_request", ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> serverError(Exception ex) {
        log.error("500 server_error cid={} {}", cid(), ex.getMessage(), ex);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "server_error", null);
    }
}
