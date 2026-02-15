package org.hat.cyberscout.camunda;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("logPolicyBlockedDelegate")
public class LogPolicyBlockedDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(LogPolicyBlockedDelegate.class);

    @Override
    public void execute(DelegateExecution execution) {
        log.warn("Attack blocked by policy for target {} reasons={}",
                execution.getVariable("targetPath"),
                execution.getVariable("policyViolations"));
    }
}
