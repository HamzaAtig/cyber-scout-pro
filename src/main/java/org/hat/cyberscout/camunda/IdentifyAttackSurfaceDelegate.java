package org.hat.cyberscout.camunda;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.recon.EndpointCandidate;
import org.hat.cyberscout.recon.ReconResult;
import org.hat.cyberscout.recon.UrlReconService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("identifyAttackSurfaceDelegate")
public class IdentifyAttackSurfaceDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(IdentifyAttackSurfaceDelegate.class);

    private final UrlReconService urlReconService;

    public IdentifyAttackSurfaceDelegate(UrlReconService urlReconService) {
        this.urlReconService = urlReconService;
    }

    @Override
    public void execute(DelegateExecution execution) {
        String baseUrl = (String) execution.getVariable("baseUrl");
        if (baseUrl == null || baseUrl.isBlank()) {
            // Backward compatible fallback for existing tests/runs.
            baseUrl = "http://localhost:8080";
        }

        ReconResult recon = urlReconService.recon(baseUrl);
        execution.setVariable("baseUrl", recon.baseUri().toString());

        // Fingerprint goes to process variables for traceability in Cockpit.
        Map<String, Object> fp = new HashMap<>();
        fp.put("server", recon.fingerprint().serverHeader());
        fp.put("poweredBy", recon.fingerprint().poweredByHeader());
        fp.put("hasHsts", recon.fingerprint().hasHsts());
        fp.put("hasCsp", recon.fingerprint().hasCsp());
        fp.put("hasXFrameOptions", recon.fingerprint().hasXFrameOptions());
        fp.put("hasXContentTypeOptions", recon.fingerprint().hasXContentTypeOptions());
        execution.setVariable("fingerprint", fp);

        List<Map<String, Object>> targetList = recon.endpoints().stream()
                .map(this::toTarget)
                .toList();

        boolean hasOpenApi = recon.endpoints().stream().anyMatch(e -> "OPENAPI".equalsIgnoreCase(e.techHint()));
        boolean hasActuator = recon.endpoints().stream().anyMatch(e -> e.path() != null && e.path().startsWith("/actuator"));
        boolean hasH2Console = recon.endpoints().stream().anyMatch(e -> "/h2-console".equalsIgnoreCase(e.path()));
        boolean apiLikely = hasOpenApi
                || recon.endpoints().stream().anyMatch(e -> e.path() != null && (e.path().startsWith("/api") || e.path().startsWith("/graphql")));

        execution.setVariable("hasOpenApi", hasOpenApi);
        execution.setVariable("hasActuator", hasActuator);
        execution.setVariable("hasH2Console", hasH2Console);
        execution.setVariable("apiLikely", apiLikely);

        execution.setVariable("targetList", targetList);
        execution.setVariable("targetCount", targetList.size());
        if (execution.getVariable("campaignId") == null) {
            execution.setVariable("campaignId", 1L);
        }
        log.info("Identified {} targets for audit", targetList.size());
    }

    private Map<String, Object> toTarget(EndpointCandidate endpoint) {
        Map<String, Object> target = new HashMap<>();
        target.put("path", endpoint.path());
        target.put("tech", endpoint.techHint());
        target.put("method", endpoint.method());
        return target;
    }

}
