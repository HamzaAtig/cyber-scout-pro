package org.hat.cyberscout.camunda;

import java.util.Map;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.springframework.stereotype.Component;

@Component("prepareTargetContextDelegate")
public class PrepareTargetContextDelegate implements JavaDelegate {

    @Override
    @SuppressWarnings("unchecked")
    public void execute(DelegateExecution execution) {
        Map<String, Object> target = (Map<String, Object>) execution.getVariable("target");

        String path = (String) target.getOrDefault("path", "/api/unknown");
        String tech = (String) target.getOrDefault("tech", "UNKNOWN");
        String method = (String) target.getOrDefault("method", "GET");

        execution.setVariable("targetPath", path);
        execution.setVariable("tech", tech);
        execution.setVariable("httpMethod", method);
    }
}
