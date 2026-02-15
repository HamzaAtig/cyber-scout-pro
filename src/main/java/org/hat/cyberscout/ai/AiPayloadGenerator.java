package org.hat.cyberscout.ai;

import java.util.List;

public interface AiPayloadGenerator {

    GeneratedPayloads generate(String targetPath, String httpMethod, String strategy, int limit);

    record GeneratedPayloads(String source, List<String> payloads) {
    }
}

