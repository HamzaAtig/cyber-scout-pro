package org.hat.cyberscout.openapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.hat.cyberscout.policy.AttackExecutionRequest;
import org.hat.cyberscout.policy.PolicyDecision;
import org.hat.cyberscout.policy.PolicyEnforcer;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class OpenApiDocumentService {

    private static final Logger log = LoggerFactory.getLogger(OpenApiDocumentService.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final PolicyEnforcer policyEnforcer;
    private final ScanRunRepository scanRunRepository;

    public OpenApiDocumentService(ObjectMapper objectMapper, PolicyEnforcer policyEnforcer, ScanRunRepository scanRunRepository) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(Redirect.NEVER)
                .build();
        this.objectMapper = objectMapper;
        this.policyEnforcer = policyEnforcer;
        this.scanRunRepository = scanRunRepository;
    }

    public Optional<JsonNode> fetchOpenApi(Long scanRunId, URI baseUri) {
        Optional<JsonNode> doc = fetchJson(scanRunId, baseUri, "/v3/api-docs");
        if (doc.isPresent()) {
            return doc;
        }
        return fetchJson(scanRunId, baseUri, "/openapi.json");
    }

    private Optional<JsonNode> fetchJson(Long scanRunId, URI baseUri, String path) {
        URI uri = baseUri.resolve(path);

        AttackExecutionRequest req = new AttackExecutionRequest(
                uri.getHost(),
                UrlUtils.effectivePort(uri),
                "GET",
                uri.getPath() == null || uri.getPath().isBlank() ? "/" : uri.getPath(),
                1
        );
        PolicyDecision decision = policyEnforcer.evaluate(req);
        if (!decision.allowed()) {
            return Optional.empty();
        }

        long start = System.nanoTime();
        int status = 0;
        String headersText = null;
        String excerpt = null;

        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/json")
                    .header("User-Agent", "Cyber-Scout-Pro/0.1 (local)")
                    .GET()
                    .build();

            HttpResponse<byte[]> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            status = resp.statusCode();

            Map<String, String> headers = flattenHeaders(resp.headers().map());
            headersText = headers.toString();
            excerpt = excerptUtf8(resp.body(), 2000);

            if (scanRunId != null && scanRunRepository.isEnabled()) {
                scanRunRepository.insertObservation(
                        scanRunId,
                        "GET",
                        uri.toString(),
                        status,
                        durationMs(start),
                        headersText,
                        excerpt
                );
            }

            if (status / 100 != 2) {
                return Optional.empty();
            }

            // Cap to 1MB to stay safe in memory; OpenAPI docs can be large.
            byte[] body = resp.body();
            if (body == null || body.length == 0) {
                return Optional.empty();
            }
            if (body.length > 1_000_000) {
                log.warn("OpenAPI doc too large ({} bytes) at {}", body.length, uri);
                return Optional.empty();
            }
            return Optional.of(objectMapper.readTree(body));
        } catch (Exception e) {
            log.warn("OpenAPI fetch failed {}: {}", uri, e.getMessage());
            return Optional.empty();
        }
    }

    private Map<String, String> flattenHeaders(Map<String, java.util.List<String>> raw) {
        Map<String, String> out = new LinkedHashMap<>();
        raw.forEach((k, v) -> out.put(k.toLowerCase(Locale.ROOT), String.join(",", v)));
        return out;
    }

    private int durationMs(long startNano) {
        return (int) Math.min(Integer.MAX_VALUE, (System.nanoTime() - startNano) / 1_000_000L);
    }

    private String excerptUtf8(byte[] bytes, int maxChars) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        String s = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        if (s.length() <= maxChars) {
            return s;
        }
        return s.substring(0, maxChars);
    }
}

