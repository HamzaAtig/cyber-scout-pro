package org.hat.cyberscout.camunda;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("logTimeoutDelegate")
public class LogTimeoutDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(LogTimeoutDelegate.class);

    @Override
    public void execute(DelegateExecution execution) {
        log.warn("LLM operation timed out for target {}", execution.getVariable("targetPath"));
        execution.setVariable("llmTimeout", true);
    }
}
