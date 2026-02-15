package org.hat.cyberscout.scan;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.hat.cyberscout.http.HttpProbeResult;
import org.hat.cyberscout.http.HttpProber;
import org.hat.cyberscout.recon.EndpointCandidate;
import org.hat.cyberscout.recon.TechFingerprint;
import org.hat.cyberscout.scan.model.Finding;
import org.hat.cyberscout.scan.persist.ScanPersistenceProperties;
import org.junit.jupiter.api.Test;

class ReconChecksTest {

    @Test
    void shouldOnlyRunEnabledFamilies() {
        ObjectMapper om = new ObjectMapper();
        ScanPersistenceProperties props = new ScanPersistenceProperties();
        props.setActiveProbingEnabled(false);

        HttpProber prober = new HttpProber() {
            @Override
            public HttpProbeResult probe(Long scanRunId, URI baseUri, String path, String method) {
                return new HttpProbeResult(baseUri.resolve(path).toString(), method, 200, 10, Map.of("content-type", "application/json"), "{}");
            }
        };
        ReconChecks checks = new ReconChecks(om, props, prober);

        TechFingerprint fp = new TechFingerprint(null, null, false, false, false, false, Map.of());
        List<EndpointCandidate> endpoints = List.of(
                new EndpointCandidate("/v3/api-docs", "GET", "OPENAPI"),
                new EndpointCandidate("/actuator/health", "GET", "SPRING_ACTUATOR")
        );

        List<Finding> findings = checks.evaluate(
                123L,
                "http://localhost:8080",
                URI.create("http://localhost:8080"),
                fp,
                endpoints,
                List.of("SECURITY_HEADERS") // only headers family enabled
        );

        // Should contain header finding, but not actuator/openapi specific ones.
        assertThat(findings).anyMatch(f -> f.checkId().contains("MISSING_SECURITY_HEADERS"));
        assertThat(findings).noneMatch(f -> f.checkId().contains("OPENAPI"));
        assertThat(findings).noneMatch(f -> f.checkId().contains("ACTUATOR"));
    }
}
