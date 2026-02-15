package org.hat.cyberscout.camunda;

import org.camunda.bpm.engine.delegate.BpmnError;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.ai.AiPayloadGenerator;
import org.hat.cyberscout.policy.PolicyProperties;
import org.springframework.stereotype.Component;

@Component("generateCustomPayloadDelegate")
public class GenerateCustomPayloadDelegate implements JavaDelegate {

    private final PolicyProperties policyProperties;
    private final AiPayloadGenerator payloadGenerator;

    public GenerateCustomPayloadDelegate(PolicyProperties policyProperties, AiPayloadGenerator payloadGenerator) {
        this.policyProperties = policyProperties;
        this.payloadGenerator = payloadGenerator;
    }

    @Override
    public void execute(DelegateExecution execution) {
        Boolean forceInvalidPayload = (Boolean) execution.getVariable("forceInvalidPayload");
        if (Boolean.TRUE.equals(forceInvalidPayload)) {
            throw new BpmnError("INVALID_LLM_FORMAT", "Simulated invalid LLM payload format");
        }

        String path = (String) execution.getVariable("targetPath");
        String strategy = (String) execution.getVariable("strategy");
        String method = (String) execution.getVariable("httpMethod");

        int payloadLimit = policyProperties.getMaxPayloadsPerTarget();
        AiPayloadGenerator.GeneratedPayloads generated;
        try {
            generated = payloadGenerator.generate(path, method, strategy, payloadLimit);
        } catch (IllegalArgumentException e) {
            // Model returned non-JSON or unusable JSON.
            throw new BpmnError("INVALID_LLM_FORMAT", e.getMessage());
        }

        execution.setVariable("strategyUsed", strategy);
        execution.setVariable("payloads", generated.payloads());
        execution.setVariable("payloadCount", generated.payloads().size());
        execution.setVariable("payloadSource", generated.source());
    }
}
