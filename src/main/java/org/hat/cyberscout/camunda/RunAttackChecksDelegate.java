package org.hat.cyberscout.camunda;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.util.List;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.hat.cyberscout.attack.AttackProperties;
import org.hat.cyberscout.attack.checks.OpenApiAttackChecks;
import org.hat.cyberscout.openapi.OpenApiDocumentService;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("runAttackChecksDelegate")
public class RunAttackChecksDelegate implements JavaDelegate {

    private static final Logger log = LoggerFactory.getLogger(RunAttackChecksDelegate.class);

    private final AttackProperties attackProperties;
    private final OpenApiDocumentService openApiDocumentService;
    private final OpenApiAttackChecks openApiAttackChecks;
    private final ScanRunRepository scanRunRepository;

    public RunAttackChecksDelegate(
            AttackProperties attackProperties,
            OpenApiDocumentService openApiDocumentService,
            OpenApiAttackChecks openApiAttackChecks,
            ScanRunRepository scanRunRepository
    ) {
        this.attackProperties = attackProperties;
        this.openApiDocumentService = openApiDocumentService;
        this.openApiAttackChecks = openApiAttackChecks;
        this.scanRunRepository = scanRunRepository;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void execute(DelegateExecution execution) {
        if (!attackProperties.isEnabled()) {
            execution.setVariable("attackFindingCount", 0);
            return;
        }

        Long scanRunId = asLong(execution.getVariable("scanRunId"));
        String baseUrl = (String) execution.getVariable("baseUrl");
        if (baseUrl == null || baseUrl.isBlank()) {
            baseUrl = "http://localhost:8080";
        }
        URI baseUri = UrlUtils.parseBaseUrl(baseUrl);

        List<String> enabledFamilies = (List<String>) execution.getVariable("enabledCheckFamilies");
        boolean doAuthz = enabledFamilies != null && enabledFamilies.contains("OPENAPI_AUTHZ_SMOKE");
        boolean doTypeVal = enabledFamilies != null && enabledFamilies.contains("OPENAPI_TYPE_VALIDATION");

        if (!doAuthz && !doTypeVal) {
            execution.setVariable("attackFindingCount", 0);
            return;
        }

        JsonNode openApiDoc = openApiDocumentService.fetchOpenApi(scanRunId, baseUri).orElse(null);
        if (openApiDoc == null) {
            execution.setVariable("attackFindingCount", 0);
            return;
        }

        int total = 0;
        if (doAuthz) {
            List<Finding> findings = openApiAttackChecks.authzSmoke(scanRunId, baseUri, baseUrl, openApiDoc);
            total += persist(scanRunId, findings);
        }
        if (doTypeVal) {
            List<Finding> findings = openApiAttackChecks.typeValidation(scanRunId, baseUri, baseUrl, openApiDoc);
            total += persist(scanRunId, findings);
        }

        execution.setVariable("attackFindingCount", total);
        log.info("Attack checks executed findings={}", total);
    }

    private int persist(Long scanRunId, List<Finding> findings) {
        if (scanRunId == null || !scanRunRepository.isEnabled()) {
            return 0;
        }
        for (Finding f : findings) {
            scanRunRepository.insertFinding(scanRunId, f);
        }
        return findings.size();
    }

    private Long asLong(Object value) {
        if (value instanceof Long longValue) return longValue;
        if (value instanceof Integer intValue) return intValue.longValue();
        if (value instanceof String stringValue) return Long.parseLong(stringValue);
        return null;
    }
}

