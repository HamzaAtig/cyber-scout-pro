package org.hat.cyberscout.camunda;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.recon.EndpointCandidate;
import org.hat.cyberscout.recon.TechFingerprint;
import org.hat.cyberscout.scan.ReconChecks;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("runReconChecksDelegate")
public class RunReconChecksDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(RunReconChecksDelegate.class);

    private final ReconChecks reconChecks;
    private final ScanRunRepository scanRunRepository;

    public RunReconChecksDelegate(ReconChecks reconChecks, ScanRunRepository scanRunRepository) {
        this.reconChecks = reconChecks;
        this.scanRunRepository = scanRunRepository;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void execute(DelegateExecution execution) {
        Long scanRunId = asLong(execution.getVariable("scanRunId"));
        String baseUrl = (String) execution.getVariable("baseUrl");
        if (baseUrl == null || baseUrl.isBlank()) {
            baseUrl = "http://localhost:8080";
        }
        URI baseUri = UrlUtils.parseBaseUrl(baseUrl);

        List<String> enabledFamilies = (List<String>) execution.getVariable("enabledCheckFamilies");
        if (enabledFamilies == null) {
            enabledFamilies = List.of("SECURITY_HEADERS");
        }

        Map<String, Object> fpVar = (Map<String, Object>) execution.getVariable("fingerprint");
        TechFingerprint fp = new TechFingerprint(
                asString(fpVar, "server"),
                asString(fpVar, "poweredBy"),
                Boolean.TRUE.equals(fpVar.get("hasHsts")),
                Boolean.TRUE.equals(fpVar.get("hasCsp")),
                Boolean.TRUE.equals(fpVar.get("hasXFrameOptions")),
                Boolean.TRUE.equals(fpVar.get("hasXContentTypeOptions")),
                Map.of()
        );

        List<Map<String, Object>> targetList = (List<Map<String, Object>>) execution.getVariable("targetList");
        List<EndpointCandidate> endpoints = new ArrayList<>();
        if (targetList != null) {
            for (Map<String, Object> t : targetList) {
                endpoints.add(new EndpointCandidate(
                        (String) t.get("path"),
                        (String) t.get("method"),
                        (String) t.get("tech")
                ));
            }
        }

        List<Finding> findings = reconChecks.evaluate(scanRunId, baseUri.toString(), baseUri, fp, endpoints, enabledFamilies);

        if (scanRunId != null && scanRunRepository.isEnabled()) {
            for (Finding f : findings) {
                scanRunRepository.insertFinding(scanRunId, f);
            }
        }

        execution.setVariable("reconFindingCount", findings.size());
        execution.setVariable("enabledCheckFamilies", enabledFamilies);

        log.info("Recon checks executed families={} findings={}", enabledFamilies, findings.size());
    }

    private String asString(Map<String, Object> map, String key) {
        Object v = map == null ? null : map.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private Long asLong(Object value) {
        if (value instanceof Long longValue) return longValue;
        if (value instanceof Integer intValue) return intValue.longValue();
        if (value instanceof String stringValue) return Long.parseLong(stringValue);
        return null;
    }
}
