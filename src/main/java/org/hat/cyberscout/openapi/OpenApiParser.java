package org.hat.cyberscout.openapi;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

public final class OpenApiParser {

    private OpenApiParser() {
    }

    public static List<OpenApiOperation> parseOperations(JsonNode openApiRoot, int limit) {
        List<OpenApiOperation> ops = new ArrayList<>();
        if (openApiRoot == null) {
            return ops;
        }

        boolean globalSecured = isNonEmptySecurityArray(openApiRoot.get("security"));

        JsonNode paths = openApiRoot.get("paths");
        if (paths == null || !paths.isObject()) {
            return ops;
        }

        Iterator<String> pathNames = paths.fieldNames();
        while (pathNames.hasNext() && ops.size() < limit) {
            String path = pathNames.next();
            JsonNode pathItem = paths.get(path);
            if (pathItem == null || !pathItem.isObject()) {
                continue;
            }

            Iterator<String> methodNames = pathItem.fieldNames();
            while (methodNames.hasNext() && ops.size() < limit) {
                String methodKey = methodNames.next();
                String methodUpper = methodKey.toUpperCase(Locale.ROOT);
                if (!isHttpMethod(methodUpper)) {
                    continue;
                }

                JsonNode op = pathItem.get(methodKey);
                if (op == null || !op.isObject()) {
                    continue;
                }

                boolean secured = effectiveSecured(globalSecured, op.get("security"));
                String mismatchBody = jsonTypeMismatchBody(op);
                ops.add(new OpenApiOperation(path, methodUpper, secured, mismatchBody));
            }
        }

        return ops;
    }

    private static boolean isHttpMethod(String methodUpper) {
        return switch (methodUpper) {
            case "GET", "POST", "PUT", "PATCH", "DELETE" -> true;
            default -> false;
        };
    }

    private static boolean effectiveSecured(boolean globalSecured, JsonNode operationSecurity) {
        // OpenAPI: "security: []" means explicitly no security for this operation.
        if (operationSecurity != null && operationSecurity.isArray()) {
            return operationSecurity.size() > 0;
        }
        return globalSecured;
    }

    private static boolean isNonEmptySecurityArray(JsonNode node) {
        return node != null && node.isArray() && node.size() > 0;
    }

    private static String jsonTypeMismatchBody(JsonNode operation) {
        JsonNode requestBody = operation.get("requestBody");
        if (requestBody == null || !requestBody.isObject()) {
            return null;
        }

        JsonNode content = requestBody.get("content");
        if (content == null || !content.isObject()) {
            return null;
        }

        // Prefer application/json.
        JsonNode appJson = content.get("application/json");
        if (appJson == null) {
            Iterator<String> cts = content.fieldNames();
            while (cts.hasNext()) {
                String ct = cts.next();
                if (ct.toLowerCase(Locale.ROOT).contains("json")) {
                    appJson = content.get(ct);
                    break;
                }
            }
        }
        if (appJson == null || !appJson.isObject()) {
            return null;
        }

        JsonNode schema = appJson.get("schema");
        if (schema == null || !schema.isObject()) {
            return null;
        }

        // Only handle the simple case: object schema with properties.
        JsonNode type = schema.get("type");
        if (type == null || !"object".equalsIgnoreCase(type.asText())) {
            return null;
        }

        JsonNode props = schema.get("properties");
        if (props == null || !props.isObject()) {
            return null;
        }

        Iterator<String> names = props.fieldNames();
        if (!names.hasNext()) {
            return null;
        }
        String propName = names.next();
        JsonNode prop = props.get(propName);
        if (prop == null || !prop.isObject()) {
            return null;
        }

        String expected = prop.has("type") ? prop.get("type").asText() : null;
        String wrongValue = wrongValueForType(expected);
        return "{\"" + escapeJson(propName) + "\":" + wrongValue + "}";
    }

    private static String wrongValueForType(String expected) {
        if (expected == null) {
            return "\"x\"";
        }
        return switch (expected.toLowerCase(Locale.ROOT)) {
            case "string" -> "123";
            case "integer", "number" -> "\"x\"";
            case "boolean" -> "\"x\"";
            case "array" -> "{}";
            case "object" -> "\"x\"";
            default -> "\"x\"";
        };
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

