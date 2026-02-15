package org.hat.cyberscout.http;

import java.util.Map;

public record HttpProbeResult(
        String url,
        String method,
        int statusCode,
        int durationMs,
        Map<String, String> responseHeaders,
        String bodyExcerpt
) {
}

