package org.hat.cyberscout.ai;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "cyberscout.ai", name = "enabled", havingValue = "false", matchIfMissing = true)
public class DeterministicPayloadGenerator implements AiPayloadGenerator {

    @Override
    public GeneratedPayloads generate(String targetPath, String httpMethod, String strategy, int limit) {
        String method = httpMethod == null ? "GET" : httpMethod.toUpperCase(Locale.ROOT);
        List<String> payloads = new ArrayList<>();

        // Safety: generate only robustness-test payloads for JSON endpoints.
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            payloads.add("{");
            payloads.add("{\"a\":");
            payloads.add("{\"a\":[1,2,}");
            payloads.add("{\"a\":\"\\uD800\"}"); // invalid surrogate
            payloads.add("null");
        } else {
            // Non-JSON methods: no body; keep a placeholder payload list for traceability.
            payloads.add("{\"note\":\"no-body\"}");
        }

        if (limit <= 0) {
            limit = 1;
        }
        List<String> bounded = payloads.subList(0, Math.min(limit, payloads.size()));
        return new GeneratedPayloads("deterministic", bounded);
    }
}
