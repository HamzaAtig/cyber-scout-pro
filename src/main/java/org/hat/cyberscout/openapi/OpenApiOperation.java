package org.hat.cyberscout.openapi;

public record OpenApiOperation(
        String path,
        String method,
        boolean secured,
        String jsonTypeMismatchBody
) {
}

