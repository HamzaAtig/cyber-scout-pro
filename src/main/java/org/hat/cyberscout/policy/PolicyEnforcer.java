package org.hat.cyberscout.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class PolicyEnforcer {

    private final PolicyProperties properties;

    public PolicyEnforcer(PolicyProperties properties) {
        this.properties = properties;
    }

    public PolicyDecision evaluate(AttackExecutionRequest request) {
        List<String> violations = new ArrayList<>();

        if (!properties.getAllowedHosts().contains(request.host())) {
            violations.add("Host not allowed: " + request.host());
        }

        if (!properties.getAllowedPorts().contains(request.port())) {
            violations.add("Port not allowed: " + request.port());
        }

        String normalizedMethod = request.method().toUpperCase(Locale.ROOT);
        if (!properties.getAllowedMethods().contains(normalizedMethod)) {
            violations.add("HTTP method not allowed: " + request.method());
        }

        boolean pathAllowed = properties.getAllowedPathPrefixes()
                .stream()
                .anyMatch(request.path()::startsWith);
        if (!pathAllowed) {
            violations.add("Path outside allowed prefixes: " + request.path());
        }

        if (request.payloadCount() > properties.getMaxPayloadsPerTarget()) {
            violations.add("Payload count exceeds max allowed: " + request.payloadCount());
        }

        return new PolicyDecision(violations.isEmpty(), violations);
    }
}
