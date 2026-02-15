package org.hat.cyberscout.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PolicyEnforcerTest {

    @Test
    void shouldAllowRequestInsidePolicy() {
        PolicyProperties properties = new PolicyProperties();
        PolicyEnforcer enforcer = new PolicyEnforcer(properties);

        PolicyDecision decision = enforcer.evaluate(new AttackExecutionRequest(
                "localhost",
                8080,
                "POST",
                "/api/login",
                2
        ));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.reasons()).isEmpty();
    }

    @Test
    void shouldBlockRequestOutsidePolicy() {
        PolicyProperties properties = new PolicyProperties();
        properties.setAllowedHosts(Set.of("localhost"));
        properties.setAllowedPorts(Set.of(8080));
        properties.setAllowedMethods(Set.of("POST"));
        properties.setAllowedPathPrefixes(List.of("/api"));
        properties.setMaxPayloadsPerTarget(2);

        PolicyEnforcer enforcer = new PolicyEnforcer(properties);
        PolicyDecision decision = enforcer.evaluate(new AttackExecutionRequest(
                "evil.example",
                9000,
                "DELETE",
                "/admin",
                3
        ));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reasons()).hasSize(5);
    }

    @Test
    void shouldBlockOutsideAllowedPrefixes() {
        PolicyProperties properties = new PolicyProperties();
        properties.setAllowedPathPrefixes(List.of("/api"));
        PolicyEnforcer enforcer = new PolicyEnforcer(properties);

        PolicyDecision decision = enforcer.evaluate(new AttackExecutionRequest(
                "localhost",
                8080,
                "GET",
                "/admin",
                1
        ));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reasons()).anyMatch(r -> r.contains("Path outside allowed prefixes"));
    }
}
