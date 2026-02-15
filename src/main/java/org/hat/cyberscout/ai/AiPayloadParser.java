package org.hat.cyberscout.ai;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AiPayloadParser {

    private final ObjectMapper objectMapper;
    private final AiProperties aiProperties;

    public AiPayloadParser(ObjectMapper objectMapper, AiProperties aiProperties) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.aiProperties = Objects.requireNonNull(aiProperties, "aiProperties");
    }

    public List<String> parsePayloads(String rawJson, int limit) {
        if (rawJson == null) {
            throw new IllegalArgumentException("LLM output is null");
        }
        String trimmed = rawJson.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("LLM output is empty");
        }
        if (trimmed.length() > aiProperties.getMaxResponseChars()) {
            throw new IllegalArgumentException("LLM output too large");
        }

        JsonNode node;
        try {
            node = objectMapper.readTree(trimmed);
        } catch (Exception e) {
            throw new IllegalArgumentException("LLM output is not valid JSON", e);
        }

        List<String> payloads = new ArrayList<>();
        if (node.isArray()) {
            // Accept array of {payload,purpose} or array of strings.
            for (JsonNode element : node) {
                if (payloads.size() >= limit) {
                    break;
                }
                if (element.isTextual()) {
                    addIfValid(payloads, element.asText());
                    continue;
                }
                if (element.isObject()) {
                    AiPayloadItem item = objectMapper.convertValue(element, new TypeReference<AiPayloadItem>() {
                    });
                    addIfValid(payloads, item.getPayload());
                    continue;
                }
                // ignore non-supported element types
            }
        } else if (node.isObject()) {
            // Also accept {"payloads":[...]}.
            JsonNode payloadsNode = node.get("payloads");
            if (payloadsNode != null && payloadsNode.isArray()) {
                List<AiPayloadItem> items = objectMapper.convertValue(payloadsNode, new TypeReference<List<AiPayloadItem>>() {
                });
                for (AiPayloadItem item : items) {
                    if (payloads.size() >= limit) {
                        break;
                    }
                    addIfValid(payloads, item == null ? null : item.getPayload());
                }
            }
        } else {
            throw new IllegalArgumentException("LLM output must be a JSON array or object");
        }

        if (payloads.isEmpty()) {
            throw new IllegalArgumentException("No usable payloads found in LLM output");
        }

        return payloads;
    }

    private void addIfValid(List<String> out, String payload) {
        if (payload == null) {
            return;
        }
        String p = payload.trim();
        if (p.isEmpty()) {
            return;
        }
        if (p.length() > aiProperties.getMaxPayloadChars()) {
            return;
        }
        // For this project we only accept JSON bodies for robustness testing.
        // They can be invalid/malformed JSON, but should look like JSON-ish strings.
        if (!(p.startsWith("{") || p.startsWith("[") || p.equals("null"))) {
            return;
        }
        out.add(p);
    }
}

