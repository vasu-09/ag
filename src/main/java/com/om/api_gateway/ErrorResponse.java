package com.om.api_gateway;

import java.time.Instant;
import org.springframework.http.HttpStatus;

/**
 * Standard error response following RFC 7807 problem details.
 */
public record ErrorResponse(
        String type,
        String title,
        int status,
        String detail,
        Instant timestamp
) {
    public static ErrorResponse of(HttpStatus status, String detail) {
        return new ErrorResponse("about:blank", status.getReasonPhrase(), status.value(), detail, Instant.now());
    }
}