package org.hat.cyberscout.camunda;

import java.util.List;
import java.util.Locale;
import org.camunda.bpm.engine.delegate.BpmnError;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.attack.AttackProperties;
import org.hat.cyberscout.governance.GovernanceDecision;
import org.hat.cyberscout.governance.GovernanceService;
import org.hat.cyberscout.http.HttpProber;
import org.hat.cyberscout.http.HttpProbeResult;
import org.hat.cyberscout.policy.AttackExecutionRequest;
import org.hat.cyberscout.policy.PolicyDecision;
import org.hat.cyberscout.policy.PolicyEnforcer;
import org.hat.cyberscout.policy.PolicyProperties;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.model.Owasp2021;
import org.hat.cyberscout.scan.model.OwaspTop10_2025;
import org.hat.cyberscout.scan.model.Severity;
import org.hat.cyberscout.scan.persist.ScanPersistenceProperties;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.springframework.stereotype.Component;

@Component("executeAttackDelegate")
public class ExecuteAttackDelegate implements JavaDelegate {

    private final PolicyEnforcer policyEnforcer;
    private final PolicyProperties policyProperties;
    private final GovernanceService governanceService;
    private final AttackProperties attackProperties;
    private final ScanPersistenceProperties scanProperties;
    private final ScanRunRepository scanRunRepository;
    private final HttpProber httpProber;

    public ExecuteAttackDelegate(
            PolicyEnforcer policyEnforcer,
            PolicyProperties policyProperties,
            GovernanceService governanceService,
            AttackProperties attackProperties,
            ScanPersistenceProperties scanProperties,
            ScanRunRepository scanRunRepository,
            HttpProber httpProber
    ) {
        this.policyEnforcer = policyEnforcer;
        this.policyProperties = policyProperties;
        this.governanceService = governanceService;
        this.attackProperties = attackProperties;
        this.scanProperties = scanProperties;
        this.scanRunRepository = scanRunRepository;
        this.httpProber = httpProber;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void execute(DelegateExecution execution) {
        if (!attackProperties.isEnabled()) {
            execution.setVariable("responseStatus", 0);
            execution.setVariable("responseBody", "ATTACK_LEVEL_DISABLED");
            return;
        }

        String host = (String) execution.getVariable("targetHost");
        if (host == null) {
            host = "localhost";
        }

        Integer port = (Integer) execution.getVariable("targetPort");
        if (port == null) {
            port = 8080;
        }

        String method = (String) execution.getVariable("httpMethod");
        String path = (String) execution.getVariable("targetPath");
        String strategy = (String) execution.getVariable("strategyUsed");
        if (strategy == null) {
            strategy = (String) execution.getVariable("strategy");
        }
        List<String> payloads = (List<String>) execution.getVariable("payloads");

        AttackExecutionRequest request = new AttackExecutionRequest(
                host,
                port,
                method,
                path,
                payloads == null ? 1 : payloads.size()
        );

        PolicyDecision decision = policyEnforcer.evaluate(request);
        if (!decision.allowed()) {
            execution.setVariable("policyViolations", decision.reasons());
            throw new BpmnError("POLICY_BLOCKED", String.join("; ", decision.reasons()));
        }

        Long campaignId = asLong(execution.getVariable("campaignId"));
        GovernanceDecision governanceDecision = governanceService.evaluateAndRecordExecution(
                campaignId,
                path,
                method,
                strategy,
                payloads,
                policyProperties.getMaxRequestsPerTarget()
        );
        if (!governanceDecision.allowed()) {
            execution.setVariable("policyViolations", governanceDecision.reasons());
            throw new BpmnError("POLICY_BLOCKED", String.join("; ", governanceDecision.reasons()));
        }

        Long scanRunId = asLong(execution.getVariable("scanRunId"));
        String baseUrl = (String) execution.getVariable("baseUrl");
        if (baseUrl == null || baseUrl.isBlank()) {
            baseUrl = "http://" + host + ":" + port;
        }

        String httpMethod = method == null ? "GET" : method.toUpperCase(Locale.ROOT);

        // Deterministic, evidence-driven checks:
        // - AUTHZ_SMOKE: GET endpoints that look sensitive; 2xx without auth is suspicious.
        // - JSON_ROBUSTNESS: POST/PUT/PATCH should not 500 on malformed JSON; stack traces are worse.
        HttpProbeResult result;
        if (isJsonMethod(httpMethod)) {
            // Reuse payloads generated upstream (deterministic or Ollama). Bounded by policy + governance budgets.
            if (payloads != null && !payloads.isEmpty()) {
                HttpProbeResult last = null;
                for (String p : payloads) {
                    if (p == null || p.isBlank()) {
                        continue;
                    }
                    last = httpProber.probeJson(scanRunId, UrlUtils.parseBaseUrl(baseUrl), path, httpMethod, p);
                    maybePersistJsonRobustnessFinding(scanRunId, baseUrl, path, httpMethod, last);
                    // If we already hit a 5xx, no need to keep hammering.
                    if (last.statusCode() >= 500) {
                        break;
                    }
                }
                result = last == null
                        ? httpProber.probeJson(scanRunId, UrlUtils.parseBaseUrl(baseUrl), path, httpMethod, "{")
                        : last;
            } else {
                result = httpProber.probeJson(scanRunId, UrlUtils.parseBaseUrl(baseUrl), path, httpMethod, "{");
                maybePersistJsonRobustnessFinding(scanRunId, baseUrl, path, httpMethod, result);
            }
        } else {
            result = httpProber.probe(scanRunId, UrlUtils.parseBaseUrl(baseUrl), path, httpMethod);
            maybePersistAuthzSmokeFinding(scanRunId, baseUrl, path, httpMethod, result);
        }

        execution.setVariable("responseStatus", result.statusCode());
        execution.setVariable("responseBody", result.bodyExcerpt());
    }

    private Long asLong(Object value) {
        if (value instanceof Long longValue) {
            return longValue;
        }
        if (value instanceof Integer intValue) {
            return intValue.longValue();
        }
        if (value instanceof String stringValue) {
            return Long.parseLong(stringValue);
        }
        return null;
    }

    private boolean isJsonMethod(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    private void maybePersistAuthzSmokeFinding(Long scanRunId, String baseUrl, String path, String method, HttpProbeResult result) {
        if (scanRunId == null || !scanRunRepository.isEnabled()) {
            return;
        }
        if (!"GET".equalsIgnoreCase(method) || path == null) {
            return;
        }
        String p = path.toLowerCase(Locale.ROOT);
        boolean sensitive = p.contains("admin") || p.contains("internal") || p.contains("manage");
        if (!sensitive) {
            return;
        }
        if (result.statusCode() >= 200 && result.statusCode() < 300) {
            scanRunRepository.insertFinding(scanRunId, new Finding(
                    scanProperties.getDefaultStandard() == org.hat.cyberscout.scan.model.OwaspStandard.OWASP_TOP10_2025 ? OwaspTop10_2025.A01 : Owasp2021.A01,
                    "A01_AUTHZ_SMOKE_UNAUTH_2XX",
                    baseUrl + path,
                    Severity.MEDIUM,
                    0.45,
                    "Potential unauthorized access (2xx on a sensitive-looking endpoint)",
                    "{\"status\":" + result.statusCode() + "}"
            ));
        }
    }

    private void maybePersistJsonRobustnessFinding(Long scanRunId, String baseUrl, String path, String method, HttpProbeResult result) {
        if (scanRunId == null || !scanRunRepository.isEnabled()) {
            return;
        }
        // Expectation: malformed JSON should be 4xx (400/415), not 5xx.
        if (result.statusCode() >= 500) {
            scanRunRepository.insertFinding(scanRunId, new Finding(
                    // Treat as misconfiguration/error handling until we add deeper classification.
                    scanProperties.getDefaultStandard() == org.hat.cyberscout.scan.model.OwaspStandard.OWASP_TOP10_2025 ? OwaspTop10_2025.A02 : Owasp2021.A05,
                    "A05_JSON_MALFORMED_5XX",
                    baseUrl + path,
                    Severity.MEDIUM,
                    0.60,
                    "Server error on malformed JSON input",
                    "{\"status\":" + result.statusCode() + "}"
            ));
        }
        String body = result.bodyExcerpt();
        if (body != null) {
            String b = body.toLowerCase(Locale.ROOT);
            boolean verbose = b.contains("exception") || b.contains("stacktrace") || b.contains("org.springframework") || b.contains("traceback");
            if (verbose) {
                scanRunRepository.insertFinding(scanRunId, new Finding(
                        scanProperties.getDefaultStandard() == org.hat.cyberscout.scan.model.OwaspStandard.OWASP_TOP10_2025 ? OwaspTop10_2025.A02 : Owasp2021.A05,
                        "A05_VERBOSE_ERROR_LEAK",
                        baseUrl + path,
                        Severity.MEDIUM,
                        0.55,
                        "Verbose error details detected in response body",
                        "{\"status\":" + result.statusCode() + "}"
                ));
            }
        }
    }
}
