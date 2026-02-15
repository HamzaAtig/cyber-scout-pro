package org.hat.cyberscout.camunda;

import java.util.List;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.springframework.stereotype.Component;

@Component("formatRepairDelegate")
public class FormatRepairDelegate implements JavaDelegate {

    @Override
    public void execute(DelegateExecution execution) {
        String path = (String) execution.getVariable("targetPath");
        List<String> fallbackPayloads = List.of(
                "{\"path\":\"" + path + "\",\"payload\":\"{}\"}",
                "{\"path\":\"" + path + "\",\"payload\":\"[]\"}"
        );
        execution.setVariable("payloads", fallbackPayloads);
        execution.setVariable("payloadCount", fallbackPayloads.size());
        execution.setVariable("formatRepaired", true);
    }
}
