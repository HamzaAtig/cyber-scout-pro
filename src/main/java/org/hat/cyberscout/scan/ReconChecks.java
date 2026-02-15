package org.hat.cyberscout.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hat.cyberscout.recon.EndpointCandidate;
import org.hat.cyberscout.recon.TechFingerprint;
import org.hat.cyberscout.http.HttpProbeResult;
import org.hat.cyberscout.http.HttpProber;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.model.Owasp2021;
import org.hat.cyberscout.scan.model.OwaspApiTop10_2023;
import org.hat.cyberscout.scan.model.OwaspCategory;
import org.hat.cyberscout.scan.model.OwaspStandard;
import org.hat.cyberscout.scan.model.OwaspTop10_2025;
import org.hat.cyberscout.scan.model.Severity;
import org.hat.cyberscout.scan.persist.ScanPersistenceProperties;
import org.springframework.stereotype.Component;

@Component
public class ReconChecks {

    private final ObjectMapper objectMapper;
    private final ScanPersistenceProperties scanProperties;
    private final HttpProber httpProber;

    public ReconChecks(ObjectMapper objectMapper, ScanPersistenceProperties scanProperties, HttpProber httpProber) {
        this.objectMapper = objectMapper;
        this.scanProperties = scanProperties;
        this.httpProber = httpProber;
    }

    public List<Finding> evaluate(
            Long scanRunId,
            String baseUrl,
            java.net.URI baseUri,
            TechFingerprint fingerprint,
            List<EndpointCandidate> endpoints,
            List<String> enabledFamilies
    ) {
        List<Finding> findings = new ArrayList<>();

        Set<String> families = enabledFamilies == null ? Set.of() : Set.copyOf(enabledFamilies);

        if (families.isEmpty() || families.contains("SECURITY_HEADERS")) {
            findings.addAll(securityHeaders(baseUrl, fingerprint));
        }
        // Passive hints from recon: only if we're allowing exposure-related checks.
        if (families.isEmpty() || families.contains("OPENAPI_PROBE")) {
            findings.addAll(exposedDocs(scanRunId, baseUrl, baseUri, endpoints));
        }
        if (families.isEmpty() || families.contains("ACTUATOR_PROBE")) {
            findings.addAll(exposedActuator(baseUrl, endpoints));
        }
        if (families.isEmpty() || families.contains("SECURITY_HEADERS")) {
            findings.addAll(exposedH2Console(baseUrl, endpoints));
        }

        if (scanProperties.isActiveProbingEnabled()) {
            if (families.contains("OPENAPI_PROBE")) {
                findings.addAll(activeOpenApiExposure(scanRunId, baseUrl, baseUri));
            }
            if (families.contains("ACTUATOR_PROBE")) {
                findings.addAll(activeActuatorHealthExposure(scanRunId, baseUrl, baseUri));
            }
            if (families.contains("RATELIMIT_PROBE")) {
                findings.addAll(rateLimitProbeLight(scanRunId, baseUrl, baseUri));
            }
        }

        return findings;
    }

    private List<Finding> securityHeaders(String baseUrl, TechFingerprint fingerprint) {
        List<Finding> findings = new ArrayList<>();
        if (fingerprint == null) {
            return findings;
        }

        List<String> missing = new ArrayList<>();
        if (!fingerprint.hasCsp()) missing.add("Content-Security-Policy");
        if (!fingerprint.hasXFrameOptions()) missing.add("X-Frame-Options");
        if (!fingerprint.hasXContentTypeOptions()) missing.add("X-Content-Type-Options");

        // HSTS only makes sense on HTTPS.
        boolean isHttps = baseUrl != null && baseUrl.toLowerCase(Locale.ROOT).startsWith("https://");
        if (isHttps && !fingerprint.hasHsts()) {
            missing.add("Strict-Transport-Security");
        }

        if (missing.isEmpty()) {
            return findings;
        }

        OwaspCategory category = mapSecurityMisconfiguration();
        findings.add(new Finding(
                category,
                "A05_MISSING_SECURITY_HEADERS",
                baseUrl,
                Severity.LOW,
                0.85,
                "Missing recommended security headers",
                toJson(Map.of("missing", missing, "observedHeaders", fingerprint.rawHeaders()))
        ));
        return findings;
    }

    private List<Finding> exposedDocs(Long scanRunId, String baseUrl, java.net.URI baseUri, List<EndpointCandidate> endpoints) {
        if (endpoints == null) {
            return List.of();
        }
        boolean hasOpenApi = endpoints.stream().anyMatch(e -> "OPENAPI".equalsIgnoreCase(e.techHint()));
        if (!hasOpenApi) {
            return List.of();
        }
        List<Finding> findings = new ArrayList<>();

        findings.add(new Finding(
                mapSecurityMisconfiguration(),
                "A05_EXPOSED_API_DOCS",
                baseUrl,
                Severity.LOW,
                0.70,
                "API documentation appears to be exposed (OpenAPI/Swagger detected)",
                toJson(Map.of("hint", "OPENAPI", "note", "Verify if docs should be public in this environment"))
        ));

        // API Security Top 10:2023 mapping.
        findings.add(new Finding(
                OwaspApiTop10_2023.API9,
                "API9_IMPROPER_INVENTORY_OPENAPI_EXPOSED",
                baseUrl,
                Severity.LOW,
                0.65,
                "OpenAPI was discovered; ensure API inventory and exposure are intended",
                toJson(Map.of("hint", "OPENAPI", "owaspApi2023", "API9"))
        ));

        return findings;
    }

    private List<Finding> exposedActuator(String baseUrl, List<EndpointCandidate> endpoints) {
        if (endpoints == null) {
            return List.of();
        }
        boolean hasActuator = endpoints.stream().anyMatch(e -> e.path().startsWith("/actuator"));
        if (!hasActuator) {
            return List.of();
        }
        return List.of(new Finding(
                mapSecurityMisconfiguration(),
                "A05_EXPOSED_SPRING_ACTUATOR",
                baseUrl,
                Severity.MEDIUM,
                0.65,
                "Spring Boot Actuator endpoints were discovered",
                toJson(Map.of("paths", endpoints.stream().filter(e -> e.path().startsWith("/actuator")).map(EndpointCandidate::path).distinct().limit(10).toList()))
        ));
    }

    private List<Finding> exposedH2Console(String baseUrl, List<EndpointCandidate> endpoints) {
        if (endpoints == null) {
            return List.of();
        }
        boolean hasH2 = endpoints.stream().anyMatch(e -> "/h2-console".equalsIgnoreCase(e.path()));
        if (!hasH2) {
            return List.of();
        }
        return List.of(new Finding(
                mapSecurityMisconfiguration(),
                "A05_EXPOSED_H2_CONSOLE",
                baseUrl,
                Severity.HIGH,
                0.60,
                "H2 console endpoint discovered",
                toJson(Map.of("path", "/h2-console"))
        ));
    }

    private OwaspCategory mapSecurityMisconfiguration() {
        OwaspStandard std = scanProperties.getDefaultStandard();
        if (std == OwaspStandard.OWASP_TOP10_2025) {
            return OwaspTop10_2025.A02;
        }
        // Default to 2021 mapping.
        return Owasp2021.A05;
    }

    private List<Finding> activeOpenApiExposure(Long scanRunId, String baseUrl, java.net.URI baseUri) {
        // Validate exposure: actually fetch /v3/api-docs or /openapi.json and check for JSON payload.
        Optional<HttpProbeResult> ok = tryJsonEndpoint(scanRunId, baseUri, "/v3/api-docs");
        if (ok.isEmpty()) {
            ok = tryJsonEndpoint(scanRunId, baseUri, "/openapi.json");
        }
        if (ok.isEmpty()) {
            return List.of();
        }

        return List.of(new Finding(
                mapSecurityMisconfiguration(),
                "A05_OPENAPI_ACCESSIBLE",
                baseUrl,
                Severity.LOW,
                0.85,
                "OpenAPI appears accessible without authentication",
                toJson(Map.of("url", ok.get().url(), "status", ok.get().statusCode()))
        ));
    }

    private List<Finding> activeActuatorHealthExposure(Long scanRunId, String baseUrl, java.net.URI baseUri) {
        HttpProbeResult res = httpProber.probe(scanRunId, baseUri, "/actuator/health", "GET");
        if (res.statusCode() != 200) {
            return List.of();
        }
        // We keep confidence moderate because an app may expose health intentionally.
        return List.of(new Finding(
                mapSecurityMisconfiguration(),
                "A05_ACTUATOR_HEALTH_ACCESSIBLE",
                baseUrl,
                Severity.MEDIUM,
                0.70,
                "Actuator health endpoint is accessible",
                toJson(Map.of("url", res.url(), "status", res.statusCode()))
        ));
    }

    private List<Finding> rateLimitProbeLight(Long scanRunId, String baseUrl, java.net.URI baseUri) {
        // This is NOT a DoS/DDOS simulation: bounded request count, single-threaded, same endpoint.
        int n = Math.max(1, scanProperties.getRateLimitProbeRequests());
        n = Math.min(n, scanProperties.getActiveProbingMaxRequests());

        int ok = 0;
        int limited = 0;
        for (int i = 0; i < n; i++) {
            HttpProbeResult res = httpProber.probe(scanRunId, baseUri, "/", "GET");
            if (res.statusCode() == 429) {
                limited++;
            }
            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                ok++;
            }
        }

        if (limited > 0) {
            return List.of(); // rate-limiting observed, no finding
        }

        // Low confidence heuristic: if we could do N requests with no 429, rate limiting may be absent.
        return List.of(new Finding(
                OwaspApiTop10_2023.API4,
                "API4_RATE_LIMITING_NOT_OBSERVED_LIGHT",
                baseUrl,
                Severity.LOW,
                0.40,
                "No rate limiting observed in a small bounded probe",
                toJson(Map.of("requests", n, "ok2xx", ok, "note", "This is a light probe; absence of 429 does not prove missing throttling."))
        ));
    }

    private Optional<HttpProbeResult> tryJsonEndpoint(Long scanRunId, java.net.URI baseUri, String path) {
        HttpProbeResult res = httpProber.probe(scanRunId, baseUri, path, "GET");
        String ct = res.responseHeaders() == null ? null : res.responseHeaders().get("content-type");
        boolean json = ct != null && ct.toLowerCase(Locale.ROOT).contains("application/json");
        if (res.statusCode() == 200 && json) {
            return Optional.of(res);
        }
        return Optional.empty();
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return "{\"error\":\"failed_to_serialize_evidence\"}";
        }
    }
}
