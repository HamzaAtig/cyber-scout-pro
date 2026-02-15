package org.hat.cyberscout.policy;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public record AttackExecutionRequest(
        @NotBlank String host,
        @Min(1) @Max(65535) int port,
        @NotBlank String method,
        @NotBlank String path,
        @Min(1) @Max(20) int payloadCount
) {
}
