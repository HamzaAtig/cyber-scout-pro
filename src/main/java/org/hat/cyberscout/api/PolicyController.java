package org.hat.cyberscout.api;

import jakarta.validation.Valid;
import org.hat.cyberscout.policy.AttackExecutionRequest;
import org.hat.cyberscout.policy.PolicyDecision;
import org.hat.cyberscout.policy.PolicyEnforcer;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/policy")
public class PolicyController {

    private final PolicyEnforcer policyEnforcer;

    public PolicyController(PolicyEnforcer policyEnforcer) {
        this.policyEnforcer = policyEnforcer;
    }

    @PostMapping("/evaluate")
    public PolicyDecision evaluate(@Valid @RequestBody AttackExecutionRequest request) {
        return policyEnforcer.evaluate(request);
    }
}
