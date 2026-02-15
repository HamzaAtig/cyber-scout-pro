package org.hat.cyberscout.http;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.hat.cyberscout.policy.AttackExecutionRequest;
import org.hat.cyberscout.policy.PolicyDecision;
import org.hat.cyberscout.policy.PolicyEnforcer;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class HttpProbeService implements HttpProber {

    private static final Logger log = LoggerFactory.getLogger(HttpProbeService.class);

    private final HttpClient httpClient;
    private final PolicyEnforcer policyEnforcer;
    private final ScanRunRepository scanRunRepository;

    public HttpProbeService(PolicyEnforcer policyEnforcer, ScanRunRepository scanRunRepository) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(Redirect.NEVER)
                .build();
        this.policyEnforcer = policyEnforcer;
        this.scanRunRepository = scanRunRepository;
    }

    @Override
    public HttpProbeResult probe(Long scanRunId, URI baseUri, String path, String method) {
        URI target = baseUri.resolve(path == null ? "/" : path);
        String m = method == null ? "GET" : method.toUpperCase(Locale.ROOT);

        // Enforce allowlist/boundaries (host/port/path/method).
        AttackExecutionRequest req = new AttackExecutionRequest(
                target.getHost(),
                UrlUtils.effectivePort(target),
                m,
                target.getPath() == null || target.getPath().isBlank() ? "/" : target.getPath(),
                1
        );
        PolicyDecision decision = policyEnforcer.evaluate(req);
        if (!decision.allowed()) {
            throw new IllegalStateException("HTTP probe blocked by policy: " + String.join("; ", decision.reasons()));
        }

        long start = System.nanoTime();
        int status = 0;
        Map<String, String> headers = Map.of();
        String excerpt = null;

        try {
            HttpRequest request = HttpRequest.newBuilder(target)
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "Cyber-Scout-Pro/0.1 (local)")
                    .method(m, HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            status = response.statusCode();
            headers = flattenHeaders(response.headers().map());
            excerpt = excerptUtf8(response.body(), 2000);
            return new HttpProbeResult(target.toString(), m, status, durationMs(start), headers, excerpt);
        } catch (Exception e) {
            log.warn("HTTP probe failed {} {}: {}", m, target, e.getMessage());
            return new HttpProbeResult(target.toString(), m, status, durationMs(start), headers, null);
        } finally {
            if (scanRunId != null && scanRunRepository.isEnabled()) {
                scanRunRepository.insertObservation(
                        scanRunId,
                        m,
                        target.toString(),
                        status == 0 ? null : status,
                        durationMs(start),
                        headers.isEmpty() ? null : headers.toString(),
                        excerpt
                );
            }
        }
    }

    @Override
    public HttpProbeResult probeJson(Long scanRunId, URI baseUri, String path, String method, String jsonBody) {
        URI target = baseUri.resolve(path == null ? "/" : path);
        String m = method == null ? "POST" : method.toUpperCase(Locale.ROOT);

        AttackExecutionRequest req = new AttackExecutionRequest(
                target.getHost(),
                UrlUtils.effectivePort(target),
                m,
                target.getPath() == null || target.getPath().isBlank() ? "/" : target.getPath(),
                1
        );
        PolicyDecision decision = policyEnforcer.evaluate(req);
        if (!decision.allowed()) {
            throw new IllegalStateException("HTTP probe blocked by policy: " + String.join("; ", decision.reasons()));
        }

        long start = System.nanoTime();
        int status = 0;
        Map<String, String> headers = Map.of();
        String excerpt = null;

        try {
            String body = jsonBody == null ? "" : jsonBody;
            HttpRequest request = HttpRequest.newBuilder(target)
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "Cyber-Scout-Pro/0.1 (local)")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, */*")
                    .method(m, HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            status = response.statusCode();
            headers = flattenHeaders(response.headers().map());
            excerpt = excerptUtf8(response.body(), 2000);
            return new HttpProbeResult(target.toString(), m, status, durationMs(start), headers, excerpt);
        } catch (Exception e) {
            log.warn("HTTP JSON probe failed {} {}: {}", m, target, e.getMessage());
            return new HttpProbeResult(target.toString(), m, status, durationMs(start), headers, null);
        } finally {
            if (scanRunId != null && scanRunRepository.isEnabled()) {
                scanRunRepository.insertObservation(
                        scanRunId,
                        m,
                        target.toString(),
                        status == 0 ? null : status,
                        durationMs(start),
                        headers.isEmpty() ? null : headers.toString(),
                        excerpt
                );
            }
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
