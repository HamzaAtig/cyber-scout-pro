package org.hat.cyberscout.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "cyberscout.ai", name = "enabled", havingValue = "true")
public class OllamaPayloadGenerator implements AiPayloadGenerator {

    private final ChatModel chatModel;
    private final AiProperties aiProperties;
    private final AiPayloadParser payloadParser;

    public OllamaPayloadGenerator(ChatModel chatModel, AiProperties aiProperties, ObjectMapper objectMapper) {
        this.chatModel = Objects.requireNonNull(chatModel, "chatModel");
        this.aiProperties = Objects.requireNonNull(aiProperties, "aiProperties");
        this.payloadParser = new AiPayloadParser(objectMapper, aiProperties);
    }

    @Override
    public GeneratedPayloads generate(String targetPath, String httpMethod, String strategy, int limit) {
        String method = httpMethod == null ? "GET" : httpMethod.toUpperCase(Locale.ROOT);
        String path = targetPath == null ? "/" : targetPath;
        String strat = strategy == null ? "ROBUSTNESS" : strategy;

        // Keep scope intentionally narrow: robustness payloads for JSON endpoints only.
        // This avoids turning the LLM into an exploit generator.
        String system = """
                You are a security QA assistant for LOCAL-ONLY testing.
                You only generate robustness test inputs (not exploits).
                Output MUST be strict JSON only (no markdown, no prose).
                """;

        String user = """
                Target path: %s
                HTTP method: %s
                Strategy label: %s

                Generate up to %d JSON request bodies intended to test server robustness:
                - malformed/truncated JSON
                - type mismatches (string instead of number, object instead of array, etc.)
                - invalid unicode sequences
                - nulls/empties

                Rules:
                - Respond ONLY with a JSON array.
                - Each item must be either a JSON string (the request body) or an object {"payload": "...", "purpose": "..."}.
                - Payload strings should start with '{' or '[' or be exactly "null".
                """.formatted(path, method, strat, limit);

        ChatResponse response = chatModel.call(new Prompt(List.of(
                new SystemMessage(system),
                new UserMessage(user)
        )));

        String content = response.getResult().getOutput().getText();
        List<String> payloads = payloadParser.parsePayloads(content, limit);
        return new GeneratedPayloads("ollama", payloads);
    }
}
