package org.hat.cyberscout.attack.checks;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.hat.cyberscout.http.HttpProbeResult;
import org.hat.cyberscout.http.HttpProber;
import org.hat.cyberscout.openapi.OpenApiOperation;
import org.hat.cyberscout.openapi.OpenApiParser;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.model.Owasp2021;
import org.hat.cyberscout.scan.model.OwaspStandard;
import org.hat.cyberscout.scan.model.OwaspTop10_2025;
import org.hat.cyberscout.scan.model.Severity;
import org.hat.cyberscout.scan.persist.ScanPersistenceProperties;
import org.springframework.stereotype.Component;

@Component
public class OpenApiAttackChecks {

    private final HttpProber httpProber;
    private final ScanPersistenceProperties scanProperties;

    public OpenApiAttackChecks(HttpProber httpProber, ScanPersistenceProperties scanProperties) {
        this.httpProber = httpProber;
        this.scanProperties = scanProperties;
    }

    public List<Finding> authzSmoke(Long scanRunId, URI baseUri, String baseUrl, JsonNode openApiDoc) {
        List<Finding> findings = new ArrayList<>();
        List<OpenApiOperation> ops = OpenApiParser.parseOperations(openApiDoc, 200);

        int tested = 0;
        for (OpenApiOperation op : ops) {
            if (!op.secured()) {
                continue;
            }
            // Keep bounded.
            if (tested >= 10) {
                break;
            }

            String method = op.method();
            HttpProbeResult res;
            if (isBodyMethod(method)) {
                // For auth smoke, body is irrelevant; use {}.
                res = httpProber.probeJson(scanRunId, baseUri, op.path(), method, "{}");
            } else {
                res = httpProber.probe(scanRunId, baseUri, op.path(), method);
            }
            tested++;

            // Expected: 401/403. Suspicious: 2xx.
            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                findings.add(new Finding(
                        mapAccessControl(),
                        "A01_OPENAPI_SECURED_ENDPOINT_2XX_WITHOUT_AUTH",
                        res.url(),
                        Severity.HIGH,
                        0.80,
                        "OpenAPI indicates security but endpoint returned 2xx without auth",
                        "{\"method\":\"" + method + "\",\"status\":" + res.statusCode() + "}"
                ));
            }
        }

        return findings;
    }

    public List<Finding> typeValidation(Long scanRunId, URI baseUri, String baseUrl, JsonNode openApiDoc) {
        List<Finding> findings = new ArrayList<>();
        List<OpenApiOperation> ops = OpenApiParser.parseOperations(openApiDoc, 200);

        int tested = 0;
        for (OpenApiOperation op : ops) {
            if (!isBodyMethod(op.method())) {
                continue;
            }
            if (op.jsonTypeMismatchBody() == null) {
                continue;
            }
            // If operation is secured, we will likely hit 401/403; skip to avoid noise.
            if (op.secured()) {
                continue;
            }
            if (tested >= 8) {
                break;
            }

            HttpProbeResult res = httpProber.probeJson(scanRunId, baseUri, op.path(), op.method(), op.jsonTypeMismatchBody());
            tested++;

            if (res.statusCode() >= 500) {
                findings.add(new Finding(
                        mapMisconfiguration(),
                        "A05_OPENAPI_TYPE_MISMATCH_5XX",
                        res.url(),
                        Severity.MEDIUM,
                        0.70,
                        "Server error on type-mismatched JSON input (based on OpenAPI schema)",
                        "{\"method\":\"" + op.method() + "\",\"status\":" + res.statusCode() + "}"
                ));
            }

            String body = res.bodyExcerpt();
            if (body != null) {
                String b = body.toLowerCase(Locale.ROOT);
                boolean verbose = b.contains("exception") || b.contains("stacktrace") || b.contains("traceback") || b.contains("org.springframework");
                if (verbose) {
                    findings.add(new Finding(
                            mapMisconfiguration(),
                            "A05_OPENAPI_TYPE_MISMATCH_VERBOSE_ERROR",
                            res.url(),
                            Severity.MEDIUM,
                            0.60,
                            "Verbose error details detected during type-mismatch probe",
                            "{\"method\":\"" + op.method() + "\",\"status\":" + res.statusCode() + "}"
                    ));
                }
            }
        }

        return findings;
    }

    private boolean isBodyMethod(String methodUpper) {
        return "POST".equalsIgnoreCase(methodUpper) || "PUT".equalsIgnoreCase(methodUpper) || "PATCH".equalsIgnoreCase(methodUpper);
    }

    private org.hat.cyberscout.scan.model.OwaspCategory mapAccessControl() {
        return scanProperties.getDefaultStandard() == OwaspStandard.OWASP_TOP10_2025 ? OwaspTop10_2025.A01 : Owasp2021.A01;
    }

    private org.hat.cyberscout.scan.model.OwaspCategory mapMisconfiguration() {
        // 2025 maps misconfiguration to A02; 2021 to A05.
        return scanProperties.getDefaultStandard() == OwaspStandard.OWASP_TOP10_2025 ? OwaspTop10_2025.A02 : Owasp2021.A05;
    }
}

