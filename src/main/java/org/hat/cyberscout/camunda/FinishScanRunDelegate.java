package org.hat.cyberscout.camunda;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("finishScanRunDelegate")
public class FinishScanRunDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(FinishScanRunDelegate.class);

    private final ScanRunRepository scanRunRepository;

    public FinishScanRunDelegate(ScanRunRepository scanRunRepository) {
        this.scanRunRepository = scanRunRepository;
    }

    @Override
    public void execute(DelegateExecution execution) {
        Long scanRunId = asLong(execution.getVariable("scanRunId"));
        if (scanRunId == null || !scanRunRepository.isEnabled()) {
            return;
        }
        scanRunRepository.finishRun(scanRunId, "FINISHED");
        log.info("Finished scan run {}", scanRunId);
    }

    private Long asLong(Object value) {
        if (value instanceof Long longValue) return longValue;
        if (value instanceof Integer intValue) return intValue.longValue();
        if (value instanceof String stringValue) return Long.parseLong(stringValue);
        return null;
    }
}

