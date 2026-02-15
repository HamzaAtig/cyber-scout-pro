package org.hat.cyberscout.camunda;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.springframework.stereotype.Component;

@Component("analyzeResponseDelegate")
public class AnalyzeResponseDelegate implements JavaDelegate {

    @Override
    public void execute(DelegateExecution execution) {
        Integer status = (Integer) execution.getVariable("responseStatus");
        String body = (String) execution.getVariable("responseBody");

        boolean finding = status != null
                && status == 200
                && body != null
                && body.contains("sensitive-file");

        execution.setVariable("findingDetected", finding);
    }
}
