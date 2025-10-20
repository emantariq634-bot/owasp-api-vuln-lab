package edu.nu.owaspapivulnlab.web.error;

import edu.nu.owaspapivulnlab.logging.RequestCorrelationFilter;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Task 9: Input Validation error responses.
 * Maps bean validation errors to a consistent 400 JSON payload,
 * without touching previous inline comments elsewhere.
 */
@ControllerAdvice
public class ValidationErrorHandler {

    private String cid() {
        String cid = MDC.get(RequestCorrelationFilter.MDC_KEY);
        return cid == null ? "n/a" : cid;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> onInvalidBody(MethodArgumentNotValidException ex) {
        List<Map<String, String>> details = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(this::toDetail)
                .collect(Collectors.toList());

        Map<String, Object> body = new HashMap<>();
        body.put("error", "validation_error");
        body.put("correlationId", cid());
        body.put("details", details);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> onConstraintViolation(ConstraintViolationException ex) {
        List<Map<String, String>> details = ex.getConstraintViolations()
                .stream().map(this::toDetail)
                .collect(Collectors.toList());

        Map<String, Object> body = new HashMap<>();
        body.put("error", "validation_error");
        body.put("correlationId", cid());
        body.put("details", details);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private Map<String, String> toDetail(FieldError fe) {
        Map<String, String> d = new HashMap<>();
        d.put("field", fe.getField());
        d.put("message", fe.getDefaultMessage());
        return d;
    }

    private Map<String, String> toDetail(ConstraintViolation<?> cv) {
        Map<String, String> d = new HashMap<>();
        d.put("field", cv.getPropertyPath() == null ? "unknown" : cv.getPropertyPath().toString());
        d.put("message", cv.getMessage());
        return d;
    }
}
